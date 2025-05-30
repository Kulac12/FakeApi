const express = require('express')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const cors = require('cors')

const app = express()
const PORT = 4000

app.use(express.json())
app.use(cookieParser())

app.use(cors({
  origin: true,
  credentials: true
}))

const JWT_SECRET = 'sertelgizlitoken'
const JWT_EXPIRES_IN = '15m'

const fakeUser = {
  email: 'admin@test.com',
  password: '123456',
  role: 'admin'
}

function sendValidationError(res, field, message) {
  return res.status(200).json({
    ErrorType: 'validation.error',
    Data: { [field]: message },
    Success: false,
    Message: 'Doğrulama hatası oluştu. Girdiğiniz değerleri kontrol ediniz.'
  })
}

// ✅ LOGIN
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body

  // Validasyon boş mu?
  if (!email) return sendValidationError(res, 'email', 'E-posta boş olamaz')
  if (!password) return sendValidationError(res, 'password', 'Parola boş olamaz')
  if (password.length < 6) return sendValidationError(res, 'password', 'Parola en az 6 karakter olmalı')

  // Hatalı giriş
  if (email !== fakeUser.email || password !== fakeUser.password) {
    return res.status(200).json({
      success: false,
      message: 'E-posta veya şifre hatalı',
    })
  }

  // Doğru giriş
  const token = jwt.sign({ email, role: fakeUser.role }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  })

  res.cookie('accessToken', token, {
    httpOnly: true,
    secure: false,
    sameSite: 'Strict',
    maxAge: 15 * 60 * 1000,
  })

  return res.json({
    success: true,
    message: 'Giriş başarılı!',
    user: { email, role: fakeUser.role },
  })
})

// ✅ /auth/me
app.get('/auth/me', (req, res) => {
  const token = req.cookies.accessToken
  if (!token) {
    return res.status(200).json({
      success: false,
      message: 'Oturum bulunamadı.',
    })
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET)
    return res.json({
      success: true,
      user: { email: payload.email, role: payload.role },
    })
  } catch {
    return res.status(200).json({
      success: false,
      message: 'Oturum süresi dolmuş. Lütfen tekrar giriş yapın.',
    })
  }
})

// ✅ LOGOUT
app.post('/auth/logout', (req, res) => {
  res.clearCookie('accessToken')
  return res.json({
    success: true,
    message: 'Çıkış yapıldı.',
  })
})

// ✅ Server Başlat
app.listen(PORT, () => {
  console.log(`✅ Fake API running at http://localhost:${PORT}`)
})
