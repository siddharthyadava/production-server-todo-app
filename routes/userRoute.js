const express = require("express");
const {
  registerController,
  loginControler,
  forgotPasswordController,
  resetPasswordController
} = require("../controllers/userController");

//router object
const router = express.Router();

//routes
// REGISTER || POST
router.post("/register", registerController);

//LOGIN || POST
router.post("/login", loginControler);

//FORGOT PASSWORD || POST
router.post("/forgot-password", forgotPasswordController);

//RESET PASSWORD || POST
router.post("/reset-password/:token", resetPasswordController);

//export
module.exports = router;
