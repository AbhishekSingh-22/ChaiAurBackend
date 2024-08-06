import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import ApiResponse from "../utils/ApiResponse.js";

const registerUser = asyncHandler(async (req, res) => {
    // take input from user - fields which are in DB
    // check input validity
    // check whether user is present in DB or not.
    // check for images and avatar
    // upload them to cloudinary
    // if yes --> show User already registerd
    // if no --> create user object in DB (register) - then create entry in db
    // send user object as response to use it further (but remove password and refresh token)
    // redirect if needed

    const { fullName, email, username, password } = req.body;
    console.log(`email: ${email}`);

    if (
        [fullName, email, username, password].some(
            (field) => field?.trim() === ""
        )
    ) {
        throw new ApiError(400, "All fields are required.");
    }

    const existingUser = await User.findOne({
        $or: [{ username }, { email }],
    });

    if (existingUser)
        throw new ApiError(409, "User with email or username already exists.");

    const avatarLocalPath = req.files?.avatar[0]?.path;
    const coverImageLocalPath = req.files?.coverImage[0]?.path;

    if (!avatarLocalPath) throw new ApiError(400, "Avatar file is required.");

    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!avatar) throw new ApiError(400, "Avatar file is required.");

    const user = await User.create({
        fullName,
        avatar: avatar?.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase(),
    });

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    );

    if (!createdUser)
        throw new ApiError(
            500,
            "Something went wrong while registering the user"
        );

    return res
        .status(201)
        .json(
            new ApiResponse(201, createdUser, "User registered successfully.")
        );
});

export { registerUser };
