require('dotenv').config()

const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')

const app = express()
app.use(express.json())

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB connection error:', err)
    process.exit(1)
  })


const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  company: { type: String },
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
})

const User = mongoose.model('User', userSchema)

app.post('/signup', async (req, res) => {
  const { fullName, company, email, password, confirmPassword } = req.body || {}

  if (!fullName || !email || !password || !confirmPassword) {
    return res.status(400).json({ message: 'Missing required fields' })
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ message: 'Passwords do not match' })
  }

  try {
    const existingUser = await User.findOne({ email })
    if (existingUser) {
      return res.status(409).json({ message: 'Email already registered' })
    }

    const salt = await bcrypt.genSalt(10)
    const hash = await bcrypt.hash(password, salt)

    await User.create({
      fullName,
      company,
      email,
      passwordHash: hash
    })

    return res.status(201).json({ message: 'Signup successful' })
  } catch (err) {
    console.error(err)
    return res.status(500).json({ message: 'Server error' })
  }
})

app.post('/login', async (req, res) => {
  const { email, password } = req.body || {}

  if (!email || !password) {
    return res.status(400).json({ message: 'Missing email or password' })
  }

  try {
    const user = await User.findOne({ email })
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    const match = await bcrypt.compare(password, user.passwordHash)
    if (!match) {
      return res.status(401).json({ message: 'Invalid credentials' })
    }

    return res.json({ message: 'Login successful' })
  } catch (err) {
    console.error(err)
    return res.status(500).json({ message: 'Server error' })
  }
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log(`Server running on port ${PORT}`))
