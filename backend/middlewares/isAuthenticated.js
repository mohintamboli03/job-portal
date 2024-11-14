import jwt from "jsonwebtoken";

const isAuthenticated = (req, res, next) => {
    try {
        const token = req.cookies.token;
        if (!token) {
            return res.status(401).json({
                message: "User not authenticated",
                success: false,
            });
        }

        // Decode the token
        const decoded = jwt.verify(token, process.env.SECRET_KEY);
        
        // If the token is invalid or expired, jwt.verify will throw an error, so no need for an explicit check
        req.id = decoded.userId; // Add user ID from the decoded token to the request object

        next(); // Proceed to the next middleware or route handler
    } catch (error) {
        console.error("Authentication error:", error);
        return res.status(401).json({
            message: "Invalid or expired token",
            success: false,
        });
    }
};

export default isAuthenticated;
