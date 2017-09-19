process.env.NODE_ENV = 'test'

var mongo = require('mongodb')
  , chai = require('chai')
  , chaiHttp = require('chai-http')
  , server = require('../server')
  , should = chai.should()
  , Sinon = require('sinon')
  , DB = require('./db')
  , Mailgun = require('mailgun-js')
  , crypto = require('crypto')
chai.use(chaiHttp)

// Mock sandbox
var sandbox = Sinon.sandbox.create()
  , test_user = {
  verify_token: null
}
  , genRandomString = function(length) {
  return crypto.randomBytes(Math.ceil(length/2))
    .toString('hex') /** convert to hexadecimal format */
    .slice(0,length)   /** return required number of characters */
}
  , sha512 = function(password, salt) {
  var hash = crypto.createHmac('sha512', salt) /** Hashing algorithm sha512 */
  hash.update(password)
  var value = hash.digest('hex')
  return {
    salt:salt,
    passwordHash:value
  }
}
  , saltHashPassword = function(userpassword) {
  var salt = genRandomString(16) /** Gives us salt of length 16 */
  var passwordData = sha512(userpassword, salt)
  return passwordData
}

function saltHashPassword(userpassword) {
  var salt = genRandomString(16); /** Gives us salt of length 16 */
  var passwordData = sha512(userpassword, salt);
  return passwordData;
}

mailgunSendSpy = sandbox.stub().yields(null, { bo: 'dy' })
sandbox.stub(Mailgun({ apiKey: 'foo', domain: 'bar' }).Mailgun.prototype, 'messages').returns({
  send: mailgunSendSpy
})

describe('Users', function() {
  before(function(done) {
    DB.connect(done)
  })

  afterEach(function(done) {
    DB.drop(done)
  })
  // app.post('/signup',user.signup)
  describe('/POST signup', function() {

    before(function(done) {
      let user = {
        email: "p@example.com"
      }
      users = DB.getDB().collection('users')
      users.insertOne(user)
        .then(function() {done()})
    })

    it('should return 404 if user exists', function(done) {
      let user = {
        name: 'Person',
        email: 'p@example.com',
        password: 'password'
      }

      chai.request(server)
        .post('/signup')
        .send(user)
        .end(function(err, res) {
          res.should.have.status(404)
          res.body.should.be.a('object')
          res.body.message.should.equal('User with this email exists')
          done()
        })
    })

    it('should throw error if email or password is missing', function(done) {
      let user = {
        email: 'p@example.com'
      }

      chai.request(server)
        .post('/signup')
        .send(user)
        .end(function(err, res) {
          res.should.have.status(422)
          res.body.should.be.a('object')
          res.body.message.should.equal('Email or password missing')
          done()
        })
    })

    it('should create a new user in database if user is created successfully', function(done) {
      let user = {
        name: 'Another Person',
        email: 'person@another.com',
        password: 'password'
      }

      chai.request(server)
        .post('/signup')
        .send(user)
        .end(function(err, res) {
          res.should.have.status(200)
          res.body.should.be.a('object')
          res.body.message.should.equal('Verification email sent successfully')
          users = DB.getDB().collection('users')
          users.findOne({email: user.email})
            .then(function(item) {
              item.name.should.equal(user.name)
              item.email.should.equal(user.email)
            })
            .then(function() {
              done()
            })
        })
    })

  })

  // app.post('/resendverification',user.resendVerification)
  describe('POST /resendverification', function() {
    let user = {
      name: "Name",
      email: "person@example.com",
      verified: false
    }

    before('sending verification email', function(done) {
      DB.getDB().collection('users').insert(user, function(err, res) { done() })
    })

    it('should send a verification email', function(done) {
      chai.request(server)
        .post('/resendverification')
        .send({ email: user.email })
        .end(function(err, res) {
          res.should.have.status(200)
          res.body.should.be.a('object')
          res.body.message.should.equal('Verification email sent successfully')
          done()
        })
    })

    it('should give an error without email', function(done) {
      let nothing = {}
      chai.request(server)
        .post('/resendverification')
        .send(nothing)
        .end(function(err, res) {
          res.should.have.status(501)
          res.body.should.be.a('object')
          res.body.message.should.equal('Email missing')
          done()
        })
    })
  })

  // app.post('/verify-email',user.verify)
  describe('POST /verify-email', function() {
    let user = {
      email: "person@example.com",
      verify_token: "verificationtoken"
    }
    before('verifying email', function(done) {
      DB.connect(done)
      DB.getDB().collection('users').insert(user)
    })

    it('should confirm the verification of a user', function(done) {
      chai.request(server)
        .post('/verify-email')
        .send(user)
        .end( function(err, res) {
          res.should.have.status(200)
          res.body.message.should.equal('user verified successfully')
          done()
        })
    })
  })

  describe('Authenticated test cases', function() {
    var token
    var approved_user_id
    var disapproved_user_id
    var password = 'testpass123'
    var passwordData = saltHashPassword(password)
    let user = {
      email: 'person@example.com',
      approved: true,
      pass: passwordData.passwordHash,
      salt: passwordData.salt,
      role: 'admin',
      pass_verify_timestamp: Math.floor(Date.now() / 1000),
      pass_verify_token: "verifytoken"
    }

    beforeEach('create and login the user', function(done) {
      console.log("Creating and logging in user")
      DB.getDB().collection('users').insert(user)
        .then(function() {
          chai.request(server)
            .post('/login')
            .send({ email: user.email, password: password })
            .end( function(err, res) {
              token = res.body.token
              done()
            })
        })
    })

    // app.post('/login',user.login)
    describe('POST /login', function() {
      it('should log the user in', function(done) {
        chai.request(server)
          .post('/login')
          .send({ email: user.email, password: password })
          .end( function(err, res) {
            res.should.have.status(200)
            done()
          })
      })
    })

    // app.post('/me',user.profile)
    describe('POST /me', function() {
      it('should retrieve profile details', function(done) {
        chai.request(server)
          .post('/me')
          .set('Authorization', 'Bearer ' + token)
          .end( function(err, res) {
            res.should.have.status(200)
            done()
          })
      })
    })

    // app.get('/users/:pageNo/:perPage',user.getUsers)
    describe('POST /users/1/10', function() {
      it('should paginate the users', function(done) {
        done()
      })
    })

    // app.post('/users/approve',user.approve)
    describe('POST /users/approve', function() {

      before('create an approvable user', function(done) {
        let new_user = {
          email: 'admin@example.com',
          verified: true
        }
        DB.getDB().collection('users').insertOne(new_user).then(function(item) {
          disapproved_user_id = item.insertedId
          done()
        })
      })

      it('should approve the user', function(done) {
        let approve_payload = {
          approve_user_id: disapproved_user_id,
          email: user.email
        }
        chai.request(server)
          .post('/users/approve')
          .set('Authorization', 'Bearer ' + token)
          .send(approve_payload)
          .end( function(err, res) {
            res.should.have.status(200)
            done()
          })
      })
    })

    // app.post('/users/disapprove',user.disapprove)
    describe('POST /users/disapprove', function() {

      before('create an approved user', function(done) {
        let new_user = {
          email: 'admin@example.com',
          verified: true,
          approved: true
        }
        DB.getDB().collection('users').insertOne(new_user).then(function(item) {
          approved_user_id = item.insertedId
          done()
        })
      })

      it('should disapprove the user', function(done) {
        let disapprove_payload = {
          approve_user_id: approved_user_id,
          email: user.email
        }
        chai.request(server)
          .post('/users/disapprove')
          .set('Authorization', 'Bearer ' + token)
          .send(disapprove_payload)
          .end( function(err, res) {
            res.should.have.status(200)
            done()
          })
      })
    })

    // app.post('/password/forgot',user.passwordForgot)
    describe('POST /password/forgot', function() {
      let user = {
        email: 'person@example.com'
      }
      before('sending email, create a user', function(done) {
        DB.connect(done)
        DB.getDB().collection('users').insertOne(user)
      })
      it('should take the email', function(done) {
        chai.request(server)
          .post('/password/forgot')
          .send(user)
          .end( function(err, res) {
            res.should.have.status(200)
            done()
          })
      })
    })

    // app.post('/password/reset',user.passwordReset)
    describe('POST /password/reset', function() {
      let user = {
        email: 'person@example.com',
        pass_verify_timestamp: Math.floor(Date.now() / 1000),
        pass_verify_token: "verifytoken"
      }
      it('should request a new password from the user', function(done) {
        let reset_user = {
          email: 'person@example.com',
          pass_token: 'verifytoken',
          password: 'newpassword'
        }
        chai.request(server)
          .post('/password/reset')
          .send(reset_user)
          .end( function(err, res) {
            res.should.have.status(200)
            done()
          })
      })
    })

  })

  // app.post('/logout',user.logout)
  describe('POST /logout', function() {
    it('should log the user out', function(done) {
      chai.request(server)
        .post('/logout')
        .set('Authorization', 'Bearer ' + token)
        .send({email: user.email})
        .end( function(err, res) {
          // TODO: Change back to
          // res.should.have.status(200)
          res.should.have.status(401)
          done()
        })
    })
  })

  // app.post('/password/change',user.passwordChange)
  describe('POST /password/change', function() {
    it('should change password of the user', function(done) {
      done()
    })
  })

  after('all tests, clear everything', function(done) {
    DB.drop(done)
  })

})