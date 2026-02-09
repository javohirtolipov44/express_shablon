const express = require('express');
const orderController = require('../controllers/order.controller');

const router = express.Router();

router.get('/', orderController.renderOrder);
router.post('/place-order', orderController.placeOrder);

module.exports = router;
