const errorMiddleware = (err, req, res, next) => {
	const message = err.message;
	const statusCode = err.statusCode || 500;

	if (statusCode === 404) {
		return res.render('404', { title: 'Page not found' });
	}

	return res.render('error', { statusCode, message });
};

module.exports = errorMiddleware;
