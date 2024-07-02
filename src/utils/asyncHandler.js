function asyncHandler(fn){
    async (req,res,next) => {
        try {
            await fn();
        } catch (error) {
            res.status(error.code || 500).json({
                success: false,
                message: error.message
            })
        }
    }
}

// promise approach
// const asyncHandler2 = (fn) => (req, res, next) => {
//     Promise.resolve(fn(req, res, next))
//     .catch((error) => next(error))
// }


export {asyncHandler};