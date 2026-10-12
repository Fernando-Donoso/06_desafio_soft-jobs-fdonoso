# Desafío Soft Jobs: Autenticación y Autorización con JWT

Aplicación fullstack de registro e inicio de sesión de usuarios. El backend usa Node.js, Express y PostgreSQL, y protege las rutas con tokens JWT.

## Estructura

```
06_desafio_soft-jobs-fdonoso/
├── apoyo-desafio-soft-jobs-master/    # Frontend (React + Vite)
└── soft-jobs-backend-fdonoso/         # Backend (Node.js + Express)
```

## Requisitos

- Node.js 18 o superior
- PostgreSQL

## Base de datos

```sql
CREATE DATABASE softjobs;
\c softjobs

CREATE TABLE usuarios (
  id SERIAL PRIMARY KEY,
  email VARCHAR(50) NOT NULL UNIQUE,
  password VARCHAR(60) NOT NULL,
  rol VARCHAR(25),
  lenguage VARCHAR(20)
);
```

## Backend

```bash
cd soft-jobs-backend-fdonoso
npm install
```

Crea un archivo `.env` con estas variables (usa tus propios valores):

```
PORT=3000
DB_USER=postgres
DB_PASSWORD=
DB_HOST=localhost
DB_NAME=softjobs
JWT_SECRET=
```

Inicia el servidor:

```bash
npm run dev
```

Queda disponible en `http://localhost:3000`.

## Frontend

```bash
cd apoyo-desafio-soft-jobs-master
npm install
npm run dev
```

Queda disponible en `http://localhost:5173`. Ambos servidores deben estar corriendo a la vez.

## Rutas del backend

| Método | Ruta | Descripción | Requiere token |
|---|---|---|---|
| POST | `/usuarios` | Registra un usuario (la contraseña se guarda encriptada) | No |
| POST | `/login` | Valida credenciales y devuelve un token JWT con el email en el payload | No |
| GET | `/usuarios` | Devuelve los datos del usuario autenticado | Sí (`Authorization: Bearer <token>`) |

## Requerimientos cubiertos

- **Registrar y obtener usuarios** de la base de datos.
- **Middlewares:** verificación de credenciales, validación del token en las cabeceras y reporte de cada consulta por terminal.
- **JWT:** firma, verificación y decodificación de tokens.
- **Manejo de errores** con códigos de estado y mensajes en JSON (`{ message }`).
- **Encriptación** de contraseñas con `bcryptjs` al registrar.

## Autor

Fernando Donoso, Desafío Latam, generación g108.