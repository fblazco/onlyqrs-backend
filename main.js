// src/main.js
const express = require('express');
// const cors = require('cors'); // OJO: Descomenta esto y haz 'npm install cors' si tu frontend te tira error de CORS

const scannerRoutes = require('./routes/scanner.routes.js');

const app = express();
const PORT = 3000;

// app.use(cors()); // Descomenta esto cuando pruebes con el frontend
app.use(express.json()); // Vital para poder leer req.body

// Usamos nuestra nueva ruta
app.use('/api/scanner', scannerRoutes);

app.get('/api/health', (req, res) => {
    res.json({ message: "¡El escáner está en línea!" });
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});