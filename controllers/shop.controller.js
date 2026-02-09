const cartModel = require('../models/cart.model');
const productModel = require('../models/product.model');

class ShopController {
	async renderHome(req, res) {
		const page = req.query.page || 1;
		const limit = 2;
		const skip = (page - 1) * limit;

		const [products, countProducts] = await Promise.all([
			productModel.find().sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
			productModel.countDocuments(),
		]);

		const totalPages = Math.max(Math.ceil(countProducts / limit), 1);

		res.render('shop/home', { title: 'Shop', products, totalPages, currentPage: page });
	}

	async renderCart(req, res) {
		const user = req.session.user;
		const cart = await cartModel.findOne({ user: user._id }).populate('items.product').lean();

		if (cart === null) {
			return res.render('shop/cart', {
				title: 'Shopping Cart',
				products: [],
			});
		}

		const filteredProducts = cart.items.map(i => ({
			...i.product,
			quantity: i.quantity,
			totalPrice: (i.product.price * i.quantity).toLocaleString('en-US', {
				style: 'currency',
				currency: 'USD',
			}),
		}));

		const totalPrice = filteredProducts.reduce((sum, item) => {
			return sum + item.price * item.quantity;
		}, 0);

		res.render('shop/cart', {
			title: 'Shopping Cart',
			products: filteredProducts,
			totalPrice: totalPrice.toLocaleString('en-US', {
				style: 'currency',
				currency: 'USD',
			}),
		});
	}

	async addToCart(req, res) {
		const user = req.session.user;
		const productId = req.params.id;
		let cart = await cartModel.findOne({ user: user._id });

		if (!cart) {
			cart = new cartModel({ user: user._id, items: [] });
		}

		const existingItem = cart.items.find(i => i.product.toString() === productId);
		if (existingItem) {
			existingItem.quantity += 1;
		} else {
			cart.items.push({ product: productId, quantity: 1 });
		}

		await cart.save();
		res.redirect('/cart');
	}

	async updateCartItem(req, res) {
		const user = req.session.user;
		const productId = req.params.id;
		const { action } = req.body;

		let cart = await cartModel.findOne({ user: user._id });

		const item = cart.items.find(i => i.product.toString() === productId);
		if (!item) return res.redirect('/cart');

		if (action === 'increment') {
			item.quantity += 1;
		} else if (action === 'decrement') {
			item.quantity = Math.max(1, item.quantity - 1);
		}

		await cart.save();
		res.redirect('/cart');
	}

	async deleteFromtCart(req, res) {
		const user = req.session.user;
		const productId = req.params.id;
		let cart = await cartModel.findOne({ user: user._id });

		cart.items = cart.items.filter(c => c.product.toString() !== productId);
		await cart.save();

		res.redirect('/');
	}
}

module.exports = new ShopController();
