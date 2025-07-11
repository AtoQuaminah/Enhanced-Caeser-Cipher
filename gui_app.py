import os
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.core.window import Window
from crypto_engine import PrimeCipher, SecurityException

class CryptoApp(App):
    def build(self):
        # Set up UI
        self.layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        
        # Password input
        self.password_input = TextInput(
            hint_text='Enter encryption password',
            password=True,
            multiline=False
        )
        
        # Message input
        self.message_input = TextInput(
            hint_text='Enter message to encrypt/decrypt',
            multiline=True
        )
        
        # Buttons
        btn_layout = BoxLayout(spacing=5)
        self.encrypt_btn = Button(text='Encrypt')
        self.decrypt_btn = Button(text='Decrypt')
        self.clear_btn = Button(text='Clear')
        
        # Output
        self.output_label = Label(
            text='[b]Output:[/b]',
            markup=True,
            size_hint_y=None,
            height=100
        )
        self.output = TextInput(readonly=True)
        
        # Assemble UI
        self.layout.add_widget(Label(text='[b]Secure Prime Encryption[/b]', markup=True))
        self.layout.add_widget(self.password_input)
        self.layout.add_widget(self.message_input)
        btn_layout.add_widget(self.encrypt_btn)
        btn_layout.add_widget(self.decrypt_btn)
        btn_layout.add_widget(self.clear_btn)
        self.layout.add_widget(btn_layout)
        self.layout.add_widget(self.output_label)
        self.layout.add_widget(self.output)
        
        # Bind events
        self.encrypt_btn.bind(on_press=self.encrypt)
        self.decrypt_btn.bind(on_press=self.decrypt)
        self.clear_btn.bind(on_press=self.clear)
        
        # Initialize crypto
        self.cipher = None
        
        return self.layout

    def encrypt(self, instance):
        password = self.password_input.text.strip()
        message = self.message_input.text.strip()
        
        if not password or not message:
            self.show_error("Password and message required!")
            return
            
        try:
            self.cipher = PrimeCipher(password)
            encrypted = self.cipher.encrypt(message)
            self.output.text = encrypted
        except Exception as e:
            self.show_error(f"Encryption error: {str(e)}")

    def decrypt(self, instance):
        password = self.password_input.text.strip()
        message = self.output.text.strip() or self.message_input.text.strip()
        
        if not password or not message:
            self.show_error("Password and encrypted data required!")
            return
            
        try:
            if not self.cipher or self.cipher.password != password:
                self.cipher = PrimeCipher(password)
                
            decrypted = self.cipher.decrypt(message)
            self.output.text = decrypted
        except SecurityException as se:
            self.show_error(f"Security alert: {str(se)}")
        except Exception as e:
            self.show_error(f"Decryption error: {str(e)}")

    def clear(self, instance):
        self.password_input.text = ''
        self.message_input.text = ''
        self.output.text = ''
        if self.cipher:
            self.cipher.secure_erase([self.cipher])
            self.cipher = None

    def show_error(self, message):
        content = Label(text=message)
        popup = Popup(
            title='Error',
            content=content,
            size_hint=(0.8, 0.4)
        )    
        content.bind(size=content.setter('text_size'))
        popup.open()
        

if __name__ == '__main__':
    # Set appropriate window size for mobile
    Window.size = (360, 640)
    CryptoApp().run()