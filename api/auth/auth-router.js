const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken')
const Users = require('../users/users-model')
const bcrypt = require('bcryptjs')

router.post("/register", validateRoleName, async (req, res, next) => {
  const { username, password } = req.body
  const hPass = bcrypt.hashSync(password, 8)
  req.password = hPass
  console.log(req.role_name)
  const [registered] = await Users.add({username: username, password: hPass, role_name: req.role_name})
  res.status(201).json(registered)
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
});

const buildToken = user => {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  }
  const options = {
    expiresIn: '1d'
  }
  return jwt.sign(payload, JWT_SECRET, options)
}


router.post("/login", checkUsernameExists, async (req, res, next) => {
  const { username, password } = req.body
  await Users.findBy({username: username})
    .then(([user]) => {
      if(user && bcrypt.compareSync(password, user.password)) {
        const token = buildToken(user)
        console.log(token)
        res.status(200).json({message: `${username} is back!`, token})
      } else {
        next({ status: 401, message: 'Invalid credentials' })
      }
    })
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
});

module.exports = router;
