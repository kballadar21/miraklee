const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const twilio = require('twilio');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors({ origin: 'http://localhost:4200' }));

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Conectado a la base de datos de MongoDB Atlas');
  })
  .catch(error => {
    console.error('Error al conectar a la base de datos de MongoDB Atlas:', error);
  });

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  name: String,
  lastName: String,
  address: String,
  postalCode: String,
  dniNie: String,
  gender: String,
  dateOfBirth: Date,
  phone: String,
});

const User = mongoose.model('User', userSchema);

const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// Función para enviar correo de bienvenida
function sendWelcomeEmail(email, name) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Bienvenido/a a la aplicación',
    text: `¡Bienvenido/a, ${name}! Gracias por registrarte en nuestra aplicación.`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error al enviar el correo de bienvenida:', error);
    } else {
      console.log('Correo de bienvenida enviado:', info.response);
    }
  });
}

// Función para enviar correo de confirmación
function sendConfirmationEmail(email, verificationCode) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Confirmación de correo electrónico',
    text: `Tu código de verificación es: ${verificationCode}`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error al enviar el correo de confirmación:', error);
    } else {
      console.log('Correo de confirmación enviado:', info.response);
    }
  });
}


app.post('/register', async (req, res) => {
  try {
    const { email, password, name, lastName, city, postalCode, dniNie, gender, phone,address, dateOfBirth } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ success: false, message: 'El correo electrónico ya está registrado.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword, name, lastName, city, postalCode, dniNie, gender, phone, address, dateOfBirth });
    await user.save();

    // Enviar correo de bienvenida
    sendWelcomeEmail(email, name);

    res.status(201).json({ success: true, message: 'Usuario registrado exitosamente.' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error al registrar usuario.' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      res.status(401).json({ message: 'El correo electrónico no está registrado.' });
    } else {
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        res.status(401).json({ message: 'La contraseña es incorrecta.' });
      } else {
        const token = generateToken(user.email, user.password, user.name, user.lastName, user.city, user.postalCode, user.dniNie, user.gender, user.phone, user.address, user.dateOfBirth);
        res.status(200).json({ token });
      }
    }
  } catch (error) {
    res.status(500).json({ message: 'Error al iniciar sesión.' });
  }
});



function generateToken(email, password, name, lastName, city, postalCode, dniNie, gender, phone, address, dateOfBirth) {
  return jwt.sign({ email, password, name, lastName, city, postalCode, dniNie, gender, phone, address, dateOfBirth }, process.env.JWT_SECRET, { expiresIn: '1h' });
}

function authenticateToken(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: 'No se proporcionó un token de autenticación.' });
  }

  try {
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    req.userEmail = decodedToken.email;

    
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Token de autenticación inválido.' });
  }
}

app.get('/profile', authenticateToken, (req, res) => {
  const email = req.userEmail;
  User.findOne({ email })
    .then(user => {
      if (!user) {
        return res.status(404).json({ message: 'No se encontró el perfil del usuario.' });
      }

      res.status(200).json({ email: user.email, name: user.name, lastName: user.lastName, city: user.city, postalCode: user.postalCode, dniNie: user.dniNie, gender: user.gender, phone: user.phone, address: user.address, dateOfBirth: user.dateOfBirth });
    })
    .catch(error => {
      res.status(500).json({ message: 'Error al obtener el perfil del usuario.' });
    });
});

app.put('/profile', authenticateToken, (req, res) => {
  const email = req.userEmail;
  const { name, lastName, city, postalCode, dniNie, gender, phone, address, dateOfBirth } = req.body;

  // Verificar el formato del DNI o NIE utilizando una expresión regular
  const dniNieRegex = /^[XYZ\d]\d{7}[A-HJ-NP-TV-Z]$/i;
  if (dniNie && !dniNieRegex.test(dniNie)) {
    return res.status(400).json({ message: 'Formato de DNI o NIE inválido.' });
  }

  User.findOneAndUpdate({ email }, { name, lastName, city, postalCode, dniNie, gender, phone, address, dateOfBirth }, { new: true })
    .then(async user => {
      if (!user) {
        return res.status(404).json({ message: 'No se encontró el perfil del usuario.' });
      }

      // Enviar correo de confirmación
      const verificationCode = generateVerificationCode();
      sendConfirmationEmail(email, verificationCode);

      // Guardar el código de verificación en la base de datos del usuario
      user.verificationCode = verificationCode;
      await user.save();

      // Enviar mensaje SMS de bienvenida
      const welcomeMessage = `¡Bienvenido/a a Miraklee, ${user.name} ${user.lastName}! Gracias por registrarte en nuestra aplicación.`;
      try {
        await twilioClient.messages.create({
          body: welcomeMessage,
          from: '+13204387338', // Reemplaza con tu número de teléfono de Twilio
          to: user.phone
        });

        res.status(200).json({ email: user.email, name: user.name, lastName: user.lastName, city: user.city, postalCode: user.postalCode, dniNie: user.dniNie, gender: user.gender, phone: user.phone, address: user.address, dateOfBirth: user.dateOfBirth });
      } catch (error) {
        console.error('Error al enviar el mensaje de bienvenida:', error);
        res.status(500).json({ message: 'Error al actualizar el perfil del usuario.' });
      }
    })
    .catch(error => {
      console.error('Error al actualizar el perfil del usuario:', error);
      res.status(500).json({ message: 'Error al actualizar el perfil del usuario.' });
    });
});

// Función para generar un código de verificación aleatorio
function generateVerificationCode() {
  const characters = '0123456789';
  let code = '';

  for (let i = 0; i < 6; i++) {
    code += characters.charAt(Math.floor(Math.random() * characters.length));
  }

  return code;
}

// Ruta para verificar el código de confirmación
app.post('/verify', async (req, res) => {
  const { email, verificationCode } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(404).json({ message: 'No se encontró el perfil del usuario.' });
  }

  if (user.verificationCode === verificationCode) {
    // Actualizar el estado de confirmación del usuario
    user.isConfirmed = true;
    await user.save();

    res.status(200).json({ message: 'Cuenta activada correctamente.' });
  } else {
    res.status(400).json({ message: 'Código de verificación inválido.' });
  }
});

app.post('/logout', authenticateToken, (req, res) => {
  // Aquí es donde debes eliminar o invalidar el estado de inicio de sesión almacenado en el servidor.
  // Por ejemplo, si estás utilizando tokens de autenticación, puedes invalidar el token actual.

  res.status(200).json({ success: true, message: 'Cierre de sesión exitoso.' });
});


const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Servidor iniciado en el puerto ${port}`);
});
