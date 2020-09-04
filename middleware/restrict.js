const jwt = require("jsonwebtoken")

function restrict(role) {
	// list of roles
	// ordered in order of permissions
	// lowest permission ===>>> highest permission
	const roles = ["basic", "admin"]

	return async (req, res, next) => {
		const authError = {
			message: "Invalid credentials",
		}

		try {
			// // express-session will automatically get the session ID from the cookie
			// // header, and check to make sure it's valid and the session for this user exists.
			// if (!req.session || !req.session.user) {
			// 	return res.status(401).json(authError)
			// }

			// check for a token instead of a session

			// assume the token gets passed to the API as an 'Authorization' header
			const token = req.headers.authorization
			if (!token) {
				return res.status(401).json(authError)
			}

			// decode the token, re-sign the payload, and check if signature is valid
			jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
				if (err) {
					return res.status(401).json(authError)
				}

				// // check that decoded.userRole equals role

				// if (role !== decoded.userRole) {
				// 	res.status(403).json({
				// 		message: "You shall not pass"
				// 	})
				// 	next()
				// }

				if (role && roles.indexOf(decoded.userRole) < roles.indexOf(role)) {
					return res.status(403).json({
						message: "You shall not pass"
					})
				}

				// we know the user is authorized at this point
				// make the token's payload available to other middleware functions
				req.token = decoded

				next()
			})

			// next()
		} catch(err) {
			next(err)
		}
	}
}

module.exports = restrict