import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import ApiResponse from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

async function generateAccessTokenAndRefreshToken(userId) {
    try {
        const user = await User.findById(userId);
        const accessToken = await user.generateAccessToken();
        const refreshToken = await user.generateRefreshToken();

        user.refreshToken = refreshToken;

        await user.save({ validateBeforeSave: false });

        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(
            500,
            "Something went wrong while generating refresh and access token"
        );
    }
}

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

const loginUser = asyncHandler(async (req, res) => {
    // check for required fields
    // if email and password matches from database then login -> generate access token and and give access (generate refresh token as well).
    // send cookie
    // if not matched return user dosent exist in db

    const { email, username, password } = req.body;

    if (!email && !username)
        throw new ApiError(400, "username or email is required.");

    const user = await User.findOne({
        $or: [{ username }, { email }],
    });

    if (!user)
        throw new ApiError(
            404,
            "No user found with the provided username or email."
        );

    const passwordValid = await user.isPasswordCorrect(password);

    if (!passwordValid) throw new ApiError(401, "Invalid user credentials.");

    const { accessToken, refreshToken } =
        await generateAccessTokenAndRefreshToken(user._id);

    const loggedInUser = await User.findById(user._id).select(
        "-password -refreshToken"
    );

    const options = {
        httpOnly: true,
        secure: true,
    };

    res.status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(
                200,
                {
                    user: loggedInUser,
                    refreshToken,
                    accessToken,
                },
                "User logged in successfully."
            )
        );
});

const logoutUser = asyncHandler(async (req, res) => {
    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                refreshToken: undefined,
            },
        },
        {
            new: true,
        }
    );

    const options = {
        httpOnly: true,
        secure: true,
    };

    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User logged out successfully"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
    try {
        const incomingRefreshToken =
            req.cookies.refreshToken || req.body.refreshToken;

        if (!incomingRefreshToken)
            throw new ApiError(401, "unauthorized request.");

        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        );

        const user = await User.findById(decodedToken?._id);

        if (!user) throw new ApiError(401, "invalid refresh token");

        if (incomingRefreshToken !== user.refreshToken)
            throw new ApiError(401, "refresh token is expired or used");

        const { accessToken, newRefreshToken } =
            await generateAccessTokenAndRefreshToken(user._id);

        options = {
            httpOnly: true,
            secure: true,
        };

        res.status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    {
                        accessToken,
                        refreshToken: newRefreshToken,
                    },
                    "accessToken refreshed"
                )
            );
    } catch (error) {
        throw new ApiError(401, error.message || "invalid refresh token");
    }
});

export { registerUser, loginUser, logoutUser, refreshAccessToken };
