// config/database.js
const { Sequelize } = require('sequelize');
require('dotenv').config();

let sequelize;

// Si existe la variable DATABASE_URL (esto pasa en Render), usamos esa conexión con SSL
if (process.env.DATABASE_URL) {
  sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    logging: false,
    dialectOptions: {
      ssl: {
        require: true,
        rejectUnauthorized: false // Vital para que Render no rechace el certificado
      }
    }
  });
} else {
  // Si no hay DATABASE_URL, asumimos que estás en local con las variables separadas
  sequelize = new Sequelize(
    process.env.DB_NAME,
    process.env.DB_USERNAME,
    process.env.DB_PASSWORD,
    {
      host: process.env.DB_HOST,
      port: process.env.DB_PORT || 5432,
      dialect: 'postgres',
      logging: false,
    }
  );
}

// Probamos que la conexión esté viva
async function testConnection() {
  try {
    await sequelize.authenticate();
    console.log('✅ Conexión a PostgreSQL establecida con éxito.');
  } catch (error) {
    console.error('❌ No se pudo conectar a la base de datos:', error.message);
  }
}

testConnection();

module.exports = sequelize;