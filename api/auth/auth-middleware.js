const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken')
const Users = require('../users/users-model')

const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if(token) {
    jwt.verify(token, JWT_SECRET, (err, decodedJWT) => {
      if(err) {
        next({ status: 401, message: 'Token invalid' })
      } else {
        req.decodedJWT = decodedJWT
        next()
      }
    })
  } else {
    next({ status: 401, message: 'Token required' })
  }
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
}

const only = role_name => (req, res, next) => {
  if(req.decodedJWT.role_name === role_name) {
    next()
  } else {
    next({ status: 403, message: 'This is not for you' })
  }
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
}


const checkUsernameExists = async (req, res, next) => {
  const { username } = req.body
  console.log('checking username', username)
    return await Users.findBy({username: username})
      .then(([user]) => {
        if(!user) {
          next({ status: 401, message: 'Invalid credentials' })
        } else {
          console.log('check username has passed')
          next()
        }
      })
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
}


const validateRoleName = async (req, res, next) => {
  const { role_name, username } = req.body
  if(role_name) {
    console.log('trimming role name')
    req.role_name = role_name.trim()
  }
  if(req.role_name === '' || !req.role_name) {
    console.log('changing role to student')
    req.role_name = 'student'
    console.log(req.role_name)
  }
  if(req.role_name === 'admin') {
    console.log('role is admin')
      next({ status: 422, message: 'Role name can not be admin' })
    }
    const check = req.role_name.split('')
  if(check.length > 32) {
      console.log('longer than 32 chars')
      next({ status: 422, message: 'Role name can not be longer than 32 chars' })
    } else {
      const [duplicate] = await Users.findBy({username: username})
      if(duplicate) {
        console.log('userame found in db')
        next({status:422, message: 'username is not available'})
      } else {
        next()
      }
    }
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
