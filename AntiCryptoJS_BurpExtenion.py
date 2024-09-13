from burp import IBurpExtender, IIntruderPayloadProcessor, IIntruderPayloadGeneratorFactory, IIntruderPayloadGenerator, ITab, IContextMenuFactory
from java.awt import GridBagLayout, GridBagConstraints, Insets, Dimension
from javax.swing import JPanel, JLabel, JTextField, JButton, JTextArea, JScrollPane, JOptionPane, JMenuItem, JProgressBar, SwingWorker
from java.awt.datatransfer import StringSelection
from java.awt.Toolkit import getDefaultToolkit
from java.util import Base64
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec, IvParameterSpec
from java.security import Security
from org.bouncycastle.jce.provider import BouncyCastleProvider

# Add Bouncy Castle provider
Security.addProvider(BouncyCastleProvider())

class BurpExtender(IBurpExtender, IIntruderPayloadProcessor, IIntruderPayloadGeneratorFactory, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set up the extension
        callbacks.setExtensionName("AntiCryptoJS")
        self._log = callbacks.getStdout()
        
        # Register the payload processor and generator
        callbacks.registerIntruderPayloadProcessor(self)
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        callbacks.registerContextMenuFactory(self)
        
        # Create the UI
        self._panel = JPanel(GridBagLayout())
        c = GridBagConstraints()
        
        c.insets = Insets(5, 5, 5, 5)
        c.anchor = GridBagConstraints.WEST
        
        c.gridx = 0
        c.gridy = 0
        self._panel.add(JLabel("Algorithm:"), c)
        
        c.gridx = 1
        self._algField = JTextField("AES", 20)
        self._algField.setToolTipText("Select the encryption algorithm (AES or DES)")
        self._panel.add(self._algField, c)
        
        c.gridx = 0
        c.gridy = 1
        self._panel.add(JLabel("Key:"), c)
        
        c.gridx = 1
        self._keyField = JTextField("DefaultSecretKey", 20)
        self._keyField.setToolTipText("Enter the encryption key")
        self._panel.add(self._keyField, c)
        
        c.gridx = 0
        c.gridy = 2
        self._panel.add(JLabel("IV:"), c)
        
        c.gridx = 1
        self._ivField = JTextField("1234567891234567", 20)
        self._ivField.setToolTipText("Enter the initialization vector (IV)")
        self._panel.add(self._ivField, c)
        
        c.gridx = 0
        c.gridy = 3
        self._panel.add(JLabel("Block Size:"), c)
        
        c.gridx = 1
        self._blockSizeField = JTextField("16", 20)
        self._blockSizeField.setToolTipText("Enter the block size for padding (default is algorithm-specific)")
        self._panel.add(self._blockSizeField, c)
        
        c.gridx = 0
        c.gridy = 4
        c.gridwidth = 2
        self._panel.add(JLabel("Data:"), c)
        
        c.gridy = 5
        self._dataArea = JTextArea("", 10, 40)
        self._dataArea.setLineWrap(True)
        self._dataArea.setWrapStyleWord(True)
        scrollPane = JScrollPane(self._dataArea)
        scrollPane.setPreferredSize(Dimension(600, 200))
        self._panel.add(scrollPane, c)
        
        c.gridwidth = 1
        c.gridy = 6
        c.gridx = 0
        self._encButton = JButton("Encrypt", actionPerformed=self.encrypt)
        self._panel.add(self._encButton, c)
        
        c.gridx = 1
        self._decButton = JButton("Decrypt", actionPerformed=self.decrypt)
        self._panel.add(self._decButton, c)
        
        c.gridx = 0
        c.gridy = 7
        self._clearButton = JButton("Clear Data", actionPerformed=self.clearDataArea)
        self._panel.add(self._clearButton, c)
        
        c.gridx = 1
        self._copyButton = JButton("Copy Data", actionPerformed=self.copyDataArea)
        self._panel.add(self._copyButton, c)
        
        c.gridx = 0
        c.gridy = 8
        self._loadingIndicator = JProgressBar()
        self._loadingIndicator.setIndeterminate(True)
        self._loadingIndicator.setVisible(False)
        self._panel.add(self._loadingIndicator, c)
        
        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
    def getTabCaption(self):
        return "AntiCryptoJS"
    
    def getUiComponent(self):
        return self._panel
    
    def showErrorMessage(self, message):
        JOptionPane.showMessageDialog(self._panel, message, "Error", JOptionPane.ERROR_MESSAGE)
    
    def clearDataArea(self, event):
        self._dataArea.setText("")
    
    def copyDataArea(self, event):
        data = self._dataArea.getText().strip()
        if data:
            selection = StringSelection(data)
            clipboard = getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(selection, None)
            JOptionPane.showMessageDialog(self._panel, "Data copied to clipboard!", "Success", JOptionPane.INFORMATION_MESSAGE)
        else:
            JOptionPane.showMessageDialog(self._panel, "No data to copy!", "Warning", JOptionPane.WARNING_MESSAGE)
    
    def encrypt(self, event):
        try:
            algorithm = self._algField.getText().strip().upper()
            key = self._keyField.getText().strip()
            iv = self._ivField.getText().strip()
            data = self._dataArea.getText().strip()
            block_size = int(self._blockSizeField.getText().strip())
            
            if not self.validateInputs(algorithm, key, iv, block_size):
                return
            
            self._loadingIndicator.setVisible(True)
            worker = EncryptionWorker(self, algorithm, key, iv, data, block_size, "encrypt")
            worker.execute()
        except Exception as e:
            self.showErrorMessage("Error: {}".format(e))
    
    def decrypt(self, event):
        try:
            algorithm = self._algField.getText().strip().upper()
            key = self._keyField.getText().strip()
            iv = self._ivField.getText().strip()
            data = self._dataArea.getText().strip()
            block_size = int(self._blockSizeField.getText().strip())
            
            if not self.validateInputs(algorithm, key, iv, block_size):
                return
            
            self._loadingIndicator.setVisible(True)
            worker = EncryptionWorker(self, algorithm, key, iv, data, block_size, "decrypt")
            worker.execute()
        except Exception as e:
            self.showErrorMessage("Error: {}".format(e))
    
    def validateInputs(self, algorithm, key, iv, block_size):
        if algorithm not in ["AES", "DES"]:
            self.showErrorMessage("Unsupported algorithm. Use AES or DES.")
            return False
        
        if algorithm == "AES" and len(key) not in {16, 24, 32}:
            self.showErrorMessage("AES key must be 16, 24, or 32 bytes long.")
            return False
        elif algorithm == "DES" and len(key) != 8:
            self.showErrorMessage("DES key must be 8 bytes long.")
            return False
        
        if algorithm == "AES" and len(iv) != 16:
            self.showErrorMessage("AES IV must be 16 bytes long.")
            return False
        elif algorithm == "DES" and len(iv) != 8:
            self.showErrorMessage("DES IV must be 8 bytes long.")
            return False
        
        default_block_size = 16 if algorithm == "AES" else 8
        if block_size % default_block_size != 0:
            self.showErrorMessage("Block size must be a multiple of {} bytes.".format(default_block_size))
            return False
        
        return True
    
    def perform_encryption(self, algorithm, key, iv, data, block_size):
        key_spec = SecretKeySpec(key.encode(), algorithm)
        iv_spec = IvParameterSpec(iv.encode())
        cipher = Cipher.getInstance("{}/CBC/PKCS5Padding".format(algorithm), "BC")
        cipher.init(Cipher.ENCRYPT_MODE, key_spec, iv_spec)
        encrypted_data = cipher.doFinal(data.encode())
        return Base64.getEncoder().encodeToString(encrypted_data)
    
    def perform_decryption(self, algorithm, key, iv, data, block_size):
        key_spec = SecretKeySpec(key.encode(), algorithm)
        iv_spec = IvParameterSpec(iv.encode())
        cipher = Cipher.getInstance("{}/CBC/PKCS5Padding".format(algorithm), "BC")
        cipher.init(Cipher.DECRYPT_MODE, key_spec, iv_spec)
        decrypted_data = cipher.doFinal(Base64.getDecoder().decode(data))
        return ''.join([chr(byte) for byte in decrypted_data])
    
    # Implement IIntruderPayloadProcessor
    def getProcessorName(self):
        return "AntiCryptoJS Processor"
    
    def processPayload(self, currentPayload, originalPayload, baseValue):
        key = self._keyField.getText().strip()
        iv = self._ivField.getText().strip()
        algorithm = self._algField.getText().strip().upper()
        block_size = int(self._blockSizeField.getText().strip())
        
        try:
            data = self._helpers.bytesToString(currentPayload)
            encrypted_data = self.perform_encryption(algorithm, key, iv, data, block_size)
            return self._helpers.stringToBytes(encrypted_data)
        except Exception as e:
            self._log.write("Error processing payload: {}\n".format(e))
            return currentPayload
    
    # Implement IIntruderPayloadGeneratorFactory
    def getGeneratorName(self):
        return "AntiCryptoJS Generator"
    
    def createNewInstance(self, attack):
        return AntiCryptoJSPayloadGenerator(self, attack)
    
    # Implement IContextMenuFactory
    def createMenuItems(self, invocation):
        menu_list = []
        context = invocation.getInvocationContext()
        
        if context == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST or context == invocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
            menu_list.append(JMenuItem("Encrypt", actionPerformed=lambda x: self.context_encrypt(invocation)))
            menu_list.append(JMenuItem("Decrypt", actionPerformed=lambda x: self.context_decrypt(invocation)))
        
        return menu_list
    
    def context_encrypt(self, invocation):
        try:
            key = self._keyField.getText().strip()
            iv = self._ivField.getText().strip()
            algorithm = self._algField.getText().strip().upper()
            block_size = int(self._blockSizeField.getText().strip())
            
            if not self.validateInputs(algorithm, key, iv, block_size):
                return
            
            selected_messages = invocation.getSelectedMessages()
            if not selected_messages:
                self.showErrorMessage("No messages selected.")
                return
            
            message = selected_messages[0]
            selection_bounds = invocation.getSelectionBounds()
            selected_data = message.getRequest()[selection_bounds[0]:selection_bounds[1]]
            data_str = self._helpers.bytesToString(selected_data)
            
            encrypted_data = self.perform_encryption(algorithm, key, iv, data_str, block_size)
            encrypted_data_bytes = self._helpers.stringToBytes(encrypted_data)
            
            new_request = (message.getRequest()[:selection_bounds[0]] +
                           encrypted_data_bytes +
                           message.getRequest()[selection_bounds[1]:])
            
            message.setRequest(new_request)
        except Exception as e:
            self.showErrorMessage("Error during context encryption: {}".format(e))
    
    def context_decrypt(self, invocation):
        try:
            key = self._keyField.getText().strip()
            iv = self._ivField.getText().strip()
            algorithm = self._algField.getText().strip().upper()
            block_size = int(self._blockSizeField.getText().strip())
            
            if not self.validateInputs(algorithm, key, iv, block_size):
                return
            
            selected_messages = invocation.getSelectedMessages()
            if not selected_messages:
                self.showErrorMessage("No messages selected.")
                return
            
            message = selected_messages[0]
            selection_bounds = invocation.getSelectionBounds()
            selected_data = message.getRequest()[selection_bounds[0]:selection_bounds[1]]
            data_str = self._helpers.bytesToString(selected_data)
            
            decrypted_data = self.perform_decryption(algorithm, key, iv, data_str, block_size)
            decrypted_data_bytes = self._helpers.stringToBytes(decrypted_data)
            
            new_request = (message.getRequest()[:selection_bounds[0]] +
                           decrypted_data_bytes +
                           message.getRequest()[selection_bounds[1]:])
            
            message.setRequest(new_request)
        except Exception as e:
            self.showErrorMessage("Error during context decryption: {}".format(e))

class AntiCryptoJSPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self, extender, attack):
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        self._payloadIndex = 0
    
    def hasMorePayloads(self):
        return self._payloadIndex < 1
    
    def getNextPayload(self, baseValue):
        self._payloadIndex += 1
        return baseValue
    
    def reset(self):
        self._payloadIndex = 0

class EncryptionWorker(SwingWorker):
    def __init__(self, extender, algorithm, key, iv, data, block_size, operation):
        self._extender = extender
        self._algorithm = algorithm
        self._key = key
        self._iv = iv
        self._data = data
        self._block_size = block_size
        self._operation = operation
    
    def doInBackground(self):
        try:
            if self._operation == "encrypt":
                result = self._extender.perform_encryption(self._algorithm, self._key, self._iv, self._data, self._block_size)
            else:
                result = self._extender.perform_decryption(self._algorithm, self._key, self._iv, self._data, self._block_size)
            return result
        except Exception as e:
            return "Error: {}".format(e)
    
    def done(self):
        try:
            result = self.get()
            self._extender._dataArea.setText(result)
        except Exception as e:
            self._extender.showErrorMessage("Error: {}".format(e))
        finally:
            self._extender._loadingIndicator.setVisible(False)


if __name__ in ('__main__', 'burp'):
    BurpExtender()
