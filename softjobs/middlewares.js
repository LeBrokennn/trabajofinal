import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

// Middleware para reportar consultas
export const reportarConsultas = (req, res, next) => {
  console.log(`Ruta: ${req.method} ${req.url} - ${new Date()}`);
  next();
};

// Middleware para verificar credenciales
export const verificarCredenciales = (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email y password son obligatorios" });
  }

  next();
};

// Middleware para validar token
export const validarToken = (req, res, next) => {
  const Authorization = req.header("Authorization");

  if (!Authorization) {
    return res.status(401).json({ error: "Token no enviado" });
  }

  const token = Authorization.split("Bearer ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.email = decoded.email;
    next();
  } catch (error) {
    res.status(401).json({ error: "Token inválido" });
  }
};