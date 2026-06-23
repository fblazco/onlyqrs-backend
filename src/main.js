// src/main.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');

// 1. Importamos la conexión de la base de datos y el modelo
const sequelize = require('../config/database');
const ScanHistory = require('./models/scanHistory.model'); 

const scannerRoutes = require('./routes/scanner.routes.js');

const app = express();
const PORT = process.env.PORT || 3000; 

// ==========================================
// MIDDLEWARES
// ==========================================
// Configuramos CORS. Cuando salgan a producción, cambien '*' por la URL de su frontend en React.
app.use(cors({
    origin: '*', 
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
})); 

app.use(express.json()); 

// ==========================================
// RUTAS
// ==========================================
// Lo montamos en '/api' para que el POST de la ruta sea exactamente '/api/scan'
app.use('/api', scannerRoutes);

app.get('/api/health', (req, res) => {
    res.json({ message: "¡El escáner está en línea!" });
});

app.get('/', (req, res) => {
    res.send('🛡️ API de OnlyQRs funcionando correctamente.');
});

// ==========================================
// INICIALIZACIÓN (BD + Servidor)
// ==========================================
// .sync() revisa tus modelos y crea las tablas en Postgres si no existen
sequelize.sync({ force: false }) // Ojo: force: true borraría toda tu data en cada reinicio
    .then(() => {
        console.log('📦 Tablas de PostgreSQL sincronizadas con éxito.');
        
        // Solo levantamos el servidor si la base de datos respondió bien
        app.listen(PORT, () => {
            console.log(`🚀 Servidor de OnlyQRs corriendo en el puerto ${PORT}`);
        });
    })
    .catch(error => {
        console.error('❌ Error fatal al sincronizar la base de datos:', error.message);
    });