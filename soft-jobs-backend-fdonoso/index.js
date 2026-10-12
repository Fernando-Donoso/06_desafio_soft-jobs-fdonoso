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

const verificarToken = (req, res, next) => {
  try {
    const token = req.header('Authorization')?.split(' ')[1]
    if (!token) return res.status(401).send('Token no entregado')
    req.email = jwt.verify(token, process.env.JWT_SECRET).email
    next()
  } catch {
    res.status(401).send('Token inválido')
  }
}

app.post('/usuarios', async (req, res) => {
  try {
    const { email, password, rol, lenguage } = req.body
    const hash = bcrypt.hashSync(password, 10)
    await pool.query(
      'INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4)',
      [email, hash, rol, lenguage]
    )
    res.status(201).send('Usuario registrado con éxito')
  } catch (error) {
    res.status(500).send(error.code === '23505' ? 'El email ya existe' : 'Error al registrar')
  }
})

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body
    const { rows: [usuario], rowCount } = await pool.query(
      'SELECT * FROM usuarios WHERE email = $1', [email]
    )
    if (!rowCount || !bcrypt.compareSync(password, usuario.password)) {
      return res.status(401).send('Email o contraseña incorrecta')
    }
    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' })
    res.send(token)
  } catch {
    res.status(500).send('Error en el login')
  }
})

app.get('/usuarios', verificarToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, email, rol, lenguage FROM usuarios WHERE email = $1', [req.email]
    )
    res.json(rows)
  } catch {
    res.status(500).send('Error al obtener usuario')
  }
})

app.listen(process.env.PORT, () => console.log(`Servidor en http://localhost:${process.env.PORT}`))



