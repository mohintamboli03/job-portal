import { User } from "../models/user.model.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import getDataUri from "../utils/datauri.js";
import cloudinary from "../utils/cloudinary.js";

export const register = async (req, res) => {
  try {
    const { fullname, email, phoneNumber, password, role } = req.body;

    if (!fullname || !email || !phoneNumber || !password || !role) {
      return res.status(400).json({
        message: "Something is missing",
        success: false,
      });
    }

    let fileUri = null;
    let profilePhotoUrl = null;

    // Check if file is provided, if not, send an error message
    if (req.file) {
      const file = req.file;
      fileUri = getDataUri(file);
      const cloudResponse = await cloudinary.uploader.upload(fileUri.content);
      profilePhotoUrl = cloudResponse.secure_url;
    } else {
      return res.status(400).json({
        message: "Profile picture is required.",
        success: false,
      });
    }

    // Check if the user already exists
    const user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({
        message: "User already exists with this email.",
        success: false,
      });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create the user
    await User.create({
      fullname,
      email,
      phoneNumber,
      password: hashedPassword,
      role,
      profile: {
        profilePhoto: profilePhotoUrl, // Save the Cloudinary URL if the file is uploaded
      },
    });

    return res.status(201).json({
      message: "Account created successfully.",
      success: true,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "An error occurred while creating the account.",
      success: false,
    });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password, role } = req.body;

    if (!email || !password || !role) {
      return res.status(400).json({
        message: "Something is missing",
        success: false,
      });
    }
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({
        message: "Incorrect email or password.",
        success: false,
      });
    }
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(400).json({
        message: "Incorrect email or password.",
        success: false,
      });
    }
    // check role is correct or not
    if (role !== user.role) {
      return res.status(400).json({
        message: "Account doesn't exist with current role.",
        success: false,
      });
    }

    const tokenData = {
      userId: user._id,
    };
    const token = await jwt.sign(tokenData, process.env.SECRET_KEY, {
      expiresIn: "1d",
    });

    user = {
      _id: user._id,
      fullname: user.fullname,
      email: user.email,
      phoneNumber: user.phoneNumber,
      role: user.role,
      profile: user.profile,
    };

    return res
      .status(200)
      .cookie("token", token, {
        maxAge: 1 * 24 * 60 * 60 * 1000,
        httpsOnly: true,
        sameSite: "strict",
      })
      .json({
        message: `Welcome back ${user.fullname}`,
        user,
        success: true,
      });
  } catch (error) {
    console.log(error);
  }
};
export const logout = async (req, res) => {
  try {
    return res.status(200).cookie("token", "", { maxAge: 0 }).json({
      message: "Logged out successfully.",
      success: true,
    });
  } catch (error) {
    console.log(error);
  }
};

export const updateProfile = async (req, res) => {
    try {
      const { fullname, email, phoneNumber, bio, skills } = req.body;
  
      // Check if a file was uploaded
      let resumeUrl = null;
      let resumeOriginalName = null;
  
      if (req.file) {
        // Get file URI and upload to Cloudinary
        const fileUri = getDataUri(req.file);
        const cloudResponse = await cloudinary.uploader.upload(fileUri.content, {
          access_mode: "public",
        });
        resumeUrl = cloudResponse.secure_url;
        resumeOriginalName = req.file.originalname;
      }
  
      // Parse skills into an array if provided
      const skillsArray = skills ? skills.split(",") : undefined;
  
      // Get user ID from middleware (e.g., token-based authentication)
      const userId = req.id;
      let user = await User.findById(userId);
  
      if (!user) {
        return res.status(400).json({
          message: "User not found.",
          success: false,
        });
      }
  
      // Update fields only if they are provided in the request
      if (fullname) user.fullname = fullname;
      if (email) user.email = email;
      if (phoneNumber) user.phoneNumber = phoneNumber;
      if (bio) user.profile.bio = bio;
      if (skillsArray) user.profile.skills = skillsArray;
  
      // Update resume if a file was uploaded
      if (resumeUrl) {
        user.profile.resume = resumeUrl; // Save the Cloudinary URL
        user.profile.resumeOriginalName = resumeOriginalName; // Save the original file name
      }
  
      await user.save();
  
      // Return updated user information
      const updatedUser = {
        _id: user._id,
        fullname: user.fullname,
        email: user.email,
        phoneNumber: user.phoneNumber,
        role: user.role,
        profile: user.profile,
      };
  
      return res.status(200).json({
        message: "Profile updated successfully.",
        user: updatedUser,
        success: true,
      });
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        message: "An error occurred while updating the profile.",
        success: false,
      });
    }
  };
  