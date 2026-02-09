const cartModel = require('../models/cart.model');
const orderModel = require('../models/order.model');

class OrderController {
	async renderOrder(req, res) {
		const user = req.session.user;
		const orders = await orderModel.find({ user: user._id }).populate('products.product').lean();

		res.render('order/user', { title: 'My Orders', orders: orders });
	}

	async placeOrder(req, res) {
		const user = req.session.user;
		const cart = await cartModel
			.findOne({ user: user._id })
			.populate({ path: 'items', populate: { path: 'product', select: 'title price image' } });

		const orderProducts = cart.items.map(item => ({
			product: item.product._id,
			quantity: item.quantity,
		}));
		const totalPrice = cart.items.reduce((sum, item) => {
			return sum + item.product.price * item.quantity;
		}, 0);

		await orderModel.create({ user: user._id, products: orderProducts, totalPrice });

		cart.items = [];
		await cart.save();

		res.redirect('/orders');
	}
}

module.exports = new OrderController();
