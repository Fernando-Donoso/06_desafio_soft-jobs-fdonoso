import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import pg from 'pg'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

const app = express()
app.use(cors())
app.use(express.json())

const pool = new pg.Pool({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  allowExitOnIdle: true
})

// Middleware 2c: reporta cada consulta recibida (sin mostrar la contraseña)
const reportarConsulta = (req, res, next) => {
  const { password, ...bodySinClave } = req.body || {}
  console.log(`[${new Date().toLocaleString()}] ${req.method} ${req.url}`, bodySinClave)
  next()
}
app.use(reportarConsulta)

// Middleware 2a: verifica que lleguen las credenciales
const verificarCredenciales = (req, res, next) => {
  const { email, password } = req.body
  if (!email || !password) {
    return res.status(400).json({ message: 'Faltan credenciales: email y password son obligatorios' })
  }
  next()
}

// Middleware 2b: valida el token de la cabecera Authorization
const verificarToken = (req, res, next) => {
  try {
    const token = req.header('Authorization')?.split(' ')[1]
    if (!token) return res.status(401).json({ message: 'Token no entregado' })
    jwt.verify(token, process.env.JWT_SECRET)
    const { email } = jwt.decode(token)
    req.email = email
    next()
  } catch {
    res.status(401).json({ message: 'Token inválido o expirado' })
  }
}

// Registro
app.post('/usuarios', verificarCredenciales, async (req, res) => {
  try {
    const { email, password, rol, lenguage } = req.body

    const { rowCount } = await pool.query(
      'SELECT 1 FROM usuarios WHERE email = $1', [email]
    )
    if (rowCount) return res.status(409).json({ message: 'El email ya está registrado' })

    const hash = bcrypt.hashSync(password, 10)
    await pool.query(
      'INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4)',
      [email, hash, rol, lenguage]
    )
    res.status(201).json({ message: 'Usuario registrado con éxito' })
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ message: 'El email ya está registrado' })
    console.error(error)
    res.status(500).json({ message: 'Error al registrar el usuario' })
  }
})

// Login
app.post('/login', verificarCredenciales, async (req, res) => {
  try {
    const { email, password } = req.body
    const { rows: [usuario], rowCount } = await pool.query(
      'SELECT * FROM usuarios WHERE email = $1', [email]
    )
    if (!rowCount || !bcrypt.compareSync(password, usuario.password)) {
      return res.status(401).json({ message: 'Email o contraseña incorrecta' })
    }
    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' })
    res.send(token)
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Error en el login' })
  }
})

// Perfil (ruta protegida)
app.get('/usuarios', verificarToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, email, rol, lenguage FROM usuarios WHERE email = $1', [req.email]
    )
    res.json(rows)
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Error al obtener el usuario' })
  }
})

app.listen(process.env.PORT, () => console.log(`Servidor en http://localhost:${process.env.PORT}`))

