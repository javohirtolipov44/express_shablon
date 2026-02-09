const express = require('express');
const adminController = require('../controllers/admin.controller');
const upload = require('../utils/multer');

const router = express.Router();

router.get('/add-product', adminController.renderAddProduct);
router.post('/add-product', upload.single('myFile'), adminController.addProduct);

router.get('/products', adminController.renderProducts);

router.get('/edit-product/:id', adminController.renderEditProduct);
router.post('/edit-product/:id', upload.single('image'), adminController.editProduct);

router.post('/delete-product/:id', adminController.deleteProduct);

module.exports = router;
