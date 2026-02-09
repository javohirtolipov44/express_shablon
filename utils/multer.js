const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
	destination: function (req, file, cb) {
		cb(null, 'public/images');
	},
	filename: function (req, file, cb) {
		cb(null, Date.now() + file.originalname);
	},
});

const fileFilter = function (req, file, cb) {
	const fileTypes = /jpeg|jpg|png/;
	const extname = fileTypes.test(path.extname(file.originalname).toLowerCase());

	if (extname) {
		cb(null, true);
	} else {
		cb(new Error('Invalid file type'), false);
	}
};

const upload = multer({ storage, fileFilter });

module.exports = upload;
