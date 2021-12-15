const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
// const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model.js')
const bcrypt = require('bcryptjs')
const jwt = require("jsonwebtoken")
const { JWT_SECRET } = require("../secrets/index"); // use this secret!
// const {makeToken } = require('./auth-router')
// const { BCRYPT_ROUNDS } = require('../secrets')





router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
//     if(bcrypt.compareSync(req.body.password, req.user.password)){
//       const token = buildToken(req.user)
//       res.json({status: 201,
//         message: `${req.user.username} is back!`,
//         token,
//       })
//     }else{
//       next({
//         status: 401,
//         message: 'Invalid credentials'
//       })
//     }
// });
let user = req.body;

const rounds = process.env.BCRYPT_ROUNDS || 8;
const hash = bcrypt.hashSync(user.password, rounds);

user.password = hash;

try {
  const newUser = await Users.add(user);
  res.status(201).json(newUser);
} catch (err) {
  next(err);
}
})

  function buildToken(user){

    const payload = {
      subject: user.user_id,
      username: user.username,
      role_name: user.role_name,
    }
    const options = {
      expiresIn: "1d"
    }
   const result = jwt.sign(payload, JWT_SECRET, options)
   return result;
  }
   




router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
    const { username, password } = req.body;
    const { userFromDb } = req;
  
    if (bcrypt.compareSync(password, userFromDb.password)) {
      const payload = {
        subject: userFromDb.user_id,
        username: userFromDb.username,
        role_name: userFromDb.role_name,
      };
      const options = {
        expiresIn: "1d",
      };
      const token = jwt.sign(payload, JWT_SECRET, options);
      res.status(200).json({ message: `${username} is back!`, token });
    } else {
      next({ status: 401, message: "Invalid credentials" });
    }
})

  //   let { username, password } = req.body

  // User.findBy({ username})
  //   .then(([user]) => {
  //     if(user && bcrypt.compareSync(password, user.password)){
  //       const token = buildToken(user)

  //       res.status(200).json({
  //         message: `${user.username} is back!...`,token, })
  //     }else{
  //       next({status: 401, message: 'Invalid credentials' })
  //     }
  //   })
  //   .catch(next)
     
  //   });




module.exports = router;//buildToken;
