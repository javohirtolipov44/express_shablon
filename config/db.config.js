const { Sequelize } = require('sequelize');

const sequelize = new Sequelize('shop', 'root', 'admin1234', {
	host: 'localhost',
	dialect: 'mysql',
});

module.exports = sequelize;
