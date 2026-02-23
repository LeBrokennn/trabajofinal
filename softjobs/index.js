import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import cors from "cors";
import { pool } from "./db.js";
import {
  reportarConsultas,
  verificarCredenciales,
  validarToken,
} from "./middlewares.js";

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());
app.use(reportarConsultas);



// 🟢 REGISTRO
app.post("/usuarios", verificarCredenciales, async (req, res) => {
  try {
    const { email, password, rol, lenguage } = req.body;

    const passwordEncriptada = await bcrypt.hash(password, 10);

    const query = `
      INSERT INTO usuarios (email, password, rol, lenguage)
      VALUES ($1, $2, $3, $4)
      RETURNING id, email, rol, lenguage
    `;

    const values = [email, passwordEncriptada, rol, lenguage];

    const { rows } = await pool.query(query, values);

    res.status(201).json(rows[0]);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});



// 🟢 LOGIN
app.post("/login", verificarCredenciales, async (req, res) => {
  try {
    const { email, password } = req.body;

    const query = "SELECT * FROM usuarios WHERE email = $1";
    const { rows } = await pool.query(query, [email]);

    if (rows.length === 0) {
      return res.status(400).json({ error: "Usuario no existe" });
    }

    const usuario = rows[0];

    const passwordValida = await bcrypt.compare(password, usuario.password);

    if (!passwordValida) {
      return res.status(400).json({ error: "Contraseña incorrecta" });
    }

    const token = jwt.sign(
      { email: usuario.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});



// 🟢 OBTENER USUARIO AUTENTICADO
app.get("/usuarios", validarToken, async (req, res) => {
  try {
    const query = "SELECT id, email, rol, lenguage FROM usuarios WHERE email = $1";
    const { rows } = await pool.query(query, [req.email]);

    res.json(rows[0]);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});



app.listen(3000, () => {
  console.log("Servidor corriendo en puerto 3000 🚀");
});