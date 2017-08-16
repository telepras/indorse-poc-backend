process.env.NODE_ENV = 'test'

let mongo = require('mongodb');
let chai = require('chai')
let chaiHttp = require('chai-http')
let server = require('../server')
let should = chai.should()
var config = require('config');
chai.use(chaiHttp)

describe('Users', () => {

  describe('/GET unknown', () => {

    it('should return 404', (done) => {
      chai.request(server)
        .get('/unknown')
        .end((err, res) => {
          res.should.have.status(404)
          done()
        })
    })

  })

  describe('/POST signup', () => {
    before((done) => {
      let user = {
        email: "p@example.com"
      }
      const MongoClient = mongo.MongoClient
      MongoClient.connect(config.get('poc_mongo'), (err, db) => {
        if (err) return console.log(err)
        users = db.collection('users')
        users.insertOne(user)
          .then(() => done())
      })
    })

    afterEach((done) => {
      const MongoClient = mongo.MongoClient
      MongoClient.connect(config.get('poc_mongo'), (err, db) => {
        if (err) return console.log(err)
        users = db.collection('users')
        users.removeMany().then(() => done())
      })
    })

    it('should return 404 if user exists', (done) => {
      let user = {
        name: 'Person',
        email: 'p@example.com',
        password: 'password'
      }

      chai.request(server)
        .post('/signup')
        .send(user)
        .end((err, res) => {
          res.should.have.status(404)
          res.body.should.be.a('object')
          res.body.message.should.equal('User with this email exists')
          done()
        })
    })

    it('should throw error if email or password is missing', (done) => {
      let user = {
        email: 'p@example.com'
      }

      chai.request(server)
        .post('/signup')
        .send(user)
        .end((err, res) => {
          res.should.have.status(422)
          res.body.should.be.a('object')
          res.body.message.should.equal('Email or password missing')
          done()
        })
    })

    it('should create a new user in database if user is created successfully', (done) => {
      let user = {
        name: 'Another Person',
        email: 'person@another.com',
        password: 'password'
      }

      chai.request(server)
        .post('/signup')
        .send(user)
        .end((err, res) => {
          res.should.have.status(200)
          res.body.should.be.a('object')
          res.body.message.should.equal('Verification email sent successfully')
          const MongoClient = mongo.MongoClient
          MongoClient.connect(config.get('poc_mongo'), (err, db) => {
            if (err) return console.log(err)
            users = db.collection('users')
            users.findOne({email: user.email})
              .then((item) => {
                item.name.should.equal(user.name)
                item.email.should.equal(user.email)
              })
              .then(() => {
                done()
              })
          })
        })
    })

  })

})

// app.post('/signup',user.signup)
// app.post('/resendverification',user.resendVerification)
// app.post('/verify-email',user.verify)
// app.post('/login',user.login)
// app.post('/logout',user.logout)
// app.post('/me',user.profile)
// app.get('/users/:pageNo/:perPage',user.getUsers)
// app.post('/users/approve',user.approve)
// app.post('/users/disapprove',user.disapprove)
// app.post('/password/reset',user.passwordReset)
// app.post('/password/forgot',user.passwordForgot)
// app.post('/password/change',user.passwordChange)