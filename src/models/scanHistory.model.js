// src/models/scanHistory.model.js
const { DataTypes } = require('sequelize');
const sequelize = require('../../config/database'); // Ajusta esta ruta según cómo exportes tu instancia de sequelize

const ScanHistory = sequelize.define('ScanHistory', {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
    },
    url: {
        type: DataTypes.TEXT,
        allowNull: false,
        validate: {
            isUrl: true // Validación nativa de Sequelize
        }
    },
    score: {
        type: DataTypes.INTEGER,
        allowNull: false,
        validate: {
            min: 0,
            max: 100
        }
    },
    riskLevel: {
        type: DataTypes.STRING(20), // SAFE, LOW, MEDIUM, HIGH, CRITICAL
        allowNull: false
    },
    summary: {
        type: DataTypes.TEXT,
        allowNull: true
    },
    flags: {
        type: DataTypes.JSONB, // Usamos JSONB para guardar el array de banderas de forma eficiente en Postgres
        defaultValue: []
    },
    details: {
        type: DataTypes.JSONB, // Aquí guardamos el "Mega JSON" con la respuesta cruda de los 7 motores
        allowNull: true
    }
}, {
    tableName: 'scan_histories',
    timestamps: true, // Nos crea automáticamente las columnas 'createdAt' y 'updatedAt'
    underscored: true // Transforma camelCase a snake_case en las columnas de la BD (ej: created_at)
});

module.exports = ScanHistory;