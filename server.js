require('dotenv').config()

const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const cors = require('cors')

const app = express()

/* ======================
   MIDDLEWARE
====================== */
app.use(express.json())

app.use(cors({
  origin: [
    'http://localhost:5173',
    'https://kamdaengineering.netlify.app'
  ],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
}))

/* ======================
   HEALTH CHECK
====================== */
app.get('/health', (req, res) => {
  res.json({ status: 'ok' })
})

/* ======================
   DATABASE
====================== */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB connection error:', err)
    // ❌ DO NOT EXIT PROCESS
  })

/* ======================
   USER MODEL
====================== */
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  company: String,
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
})

const User = mongoose.model('User', userSchema)

/* ======================
   SIGNUP
====================== */
app.post('/api/auth/signup', async (req, res) => {
  const { fullName, company, email, password, confirmPassword } = req.body

 if (
  !fullName.trim() ||
  !email.trim() ||
  !password ||
  !confirmPassword
) {
  return res.status(400).json({ message: 'Missing required fields' })
}


  if (password !== confirmPassword) {
    return res.status(400).json({ message: 'Passwords do not match' })
  }

  try {
    const exists = await User.findOne({ email })
    if (exists) {
      return res.status(409).json({ message: 'Email already registered' })
    }

    const hash = await bcrypt.hash(password, 10)

    await User.create({
      fullName,
      company,
      email,
      passwordHash: hash
    })

    return res.status(201).json({
      message: 'Signup successful'
    })
  } catch (err) {
    console.error(err)
    return res.status(500).json({ message: 'Server error' })
  }
})

/* ======================
   LOGIN
====================== */
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body

  if (!email || !password) {
    return res.status(400).json({ message: 'Missing email or password' })
  }

  try {
    const user = await User.findOne({ email })
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    const ok = await bcrypt.compare(password, user.passwordHash)
    if (!ok) {
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    return res.json({
      message: 'Login successful'
    })
  } catch (err) {
    console.error(err)
    return res.status(500).json({ message: 'Server error' })
  }
})

/* ======================
   SERVER
====================== */
const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})

process.on('unhandledRejection', err => {
  console.error('Unhandled rejection:', err)
})

