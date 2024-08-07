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

const updatePassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;

    const user = await User.findById(req.user._id);

    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

    if (!isPasswordCorrect) throw new ApiError(400, "invalid old password");

    user.password = newPassword;
    user.save({ validateBeforeSave: false });

    res.status(200).json(
        new ApiResponse(200, {}, "Password changed successfully.")
    );
});

const getCurrentUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id).select(
        "-password -refreshToken"
    );

    if (!user) throw new ApiError(400, "No user logged in");

    res.status(200).json(
        new ApiResponse(200, user, "User fetched successfully")
    );
});

const updateAccountDetails = asyncHandler(async (req, res) => {
    const { fullName, email } = req.body;

    if (!fullName || !email) throw new ApiError(400, "All fields are required");

    const user = User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName,
                email,
            },
        },
        {
            new: true,
        }
    ).select("-password -refreshToken");

    if (!user)
        throw new ApiError(
            400,
            "Something went wrong while updating account details"
        );

    res.status(200).json(
        new ApiResponse(200, user, "Account details updated successfully")
    );
});

const updateUserAvatar = asyncHandler(async (req, res) => {
    const avatarLocalPath = await req.file?.path;

    if (!avatarLocalPath) throw new ApiError(400, "Avatar file is missing");

    const avatar = await uploadOnCloudinary(avatarLocalPath);

    if (!avatar.url)
        throw new ApiError(
            400,
            "Something went wrong while uploading avatar on cloudinary"
        );

    const user = await User.findByIdAndUpdate(
        req.body._id,
        {
            $set: {
                avatar: avatar.url,
            },
        },
        {
            new: true,
        }
    ).select("-password -refreshToken");

    res.status(200).json(
        new ApiResponse(200, user, "Avatar image updated successfully")
    );
});

const updateUserCoverImage = asyncHandler(async (req, res) => {
    const coverImageLocalPath = await req.file?.path;

    if (!coverImageLocalPath) throw new ApiError(400, "Avatar file is missing");

    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!coverImage.url)
        throw new ApiError(
            400,
            "Something went wrong while uploading avatar on cloudinary"
        );

    const user = await User.findByIdAndUpdate(
        req.body._id,
        {
            $set: {
                avatar: coverImage.url,
            },
        },
        {
            new: true,
        }
    ).select("-password -refreshToken");

    res.status(200).json(
        new ApiResponse(200, user, "Cover image updated successfully")
    );
});

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    updatePassword,
    getCurrentUser,
    updateUserAvatar,
    updateUserCoverImage,
};
