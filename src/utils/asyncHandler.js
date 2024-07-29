function asyncHandler(fn) {
    return async (req, res, next) => {
        try {
            await fn(req, res, next);
        } catch (error) {
            res.status(error.code || 500).json({
                success: false,
                message: error.message,
            });
        }
    };
}

// promise approach
// const asyncHandler = (fn) => (req, res, next) => {
//     return Promise.resolve(fn(req, res, next)).catch((error) => next(error));
// };

export { asyncHandler };
