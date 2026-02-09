const mongoose = require('mongoose');

const cartSchema = new mongoose.Schema(
	{
		user: { type: mongoose.Schema.Types.ObjectId, ref: 'user', required: true },
		items: [
			{
				quantity: { type: Number, default: 1 },
				product: { type: mongoose.Schema.Types.ObjectId, ref: 'product' },
			},
		],
	},
	{ timestamps: true }
);

module.exports = mongoose.model('cart', cartSchema);
