const hbsHelper = {
	calcTotal: (price, quantity) => {
		const total = price * quantity;
		return total.toLocaleString('en-US', {
			style: 'currency',
			currency: 'USD',
		});
	},

	formatUSD: price => {
		return price.toLocaleString('en-US', {
			style: 'currency',
			currency: 'USD',
		});
	},

	formatDate: date => {
		const d = new Date(date);
		return d.toISOString().split('T')[0];
	},

	eq: (a, b) => a == b,

	add: (a, b) => +a + b,

	sub: (a, b) => +a - b,

	range: (from, to) => {
		const arr = [];
		for (let i = from; i <= to; i++) {
			arr.push(i);
		}
		return arr;
	},
};

module.exports = hbsHelper;
