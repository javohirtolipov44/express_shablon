const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema(
	{
		user: { type: mongoose.Schema.Types.ObjectId, ref: 'user', required: true },
		products: [
			{
				quantity: { type: Number, default: 1 },
				product: { type: mongoose.Schema.Types.ObjectId, ref: 'product' },
			},
		],
		totalPrice: { type: Number, required: true },
	},
	{ timestamps: true }
);

module.exports = mongoose.model('order', orderSchema);
