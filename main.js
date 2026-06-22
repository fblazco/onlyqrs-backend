// src/main.js
const express = require('express');
//const cors = require('cors'); // <-- 1. Descomentado

const scannerRoutes = require('./routes/scanner.routes.js');

const app = express();
// <-- 2. Puerto dinámico para Render, o 3000 en local
const PORT = process.env.PORT || 3000; 

//app.use(cors()); // <-- 3. Descomentado (Permite peticiones externas)
app.use(express.json()); 

app.use('/api/scanner', scannerRoutes);

app.get('/api/health', (req, res) => {
    res.json({ message: "¡El escáner está en línea!" });
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en el puerto ${PORT}`);
});