const express = require('express');
const shopController = require('../controllers/shop.controller');
const authMiddleware = require('../middlewares/auth.middleware');

const router = express.Router();

router.get('/', shopController.renderHome);

router.get('/cart', authMiddleware, shopController.renderCart);
router.post('/cart/:id', authMiddleware, shopController.addToCart);

router.post('/cart/update/:id', authMiddleware, shopController.updateCartItem);

router.post('/cart/delete/:id', authMiddleware, shopController.deleteFromtCart);

module.exports = router;
