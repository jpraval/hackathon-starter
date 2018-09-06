const bcrypt = require('bcrypt-nodejs');
const crypto = require('crypto');
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  passwordResetToken: String,
  passwordResetExpires: Date,
  role:{type: String},

  numhoursavailable: {type: Number},
  numhoursrequired: {type: Number},
  careagesavailablefor: {type: Array},
  careagesrequired: {type: Array},
  contactname: {type: String},
  mobile: {type: String},
  address: {type: String},
  pincode: {type: String},
  typeofprovider: {type: Array},
  typeofservices: {type: Array},
  facebook: String,
  twitter: String,
  google: String,
  github: String,
  instagram: String,
  linkedin: String,
  steam: String,
  tokens: Array,

  profile: {
    name: String,
    familyRole1:String,
    familyRole2:String,
    parent1:String,
    parent2:String,
    childAge:String,
    numChild:Number,
    gender: String,
    dateOfBirth: Date, 
    location: {
      coordinates:{
        longitude:Number,
        latitude:Number
      },
      precision:Number,
      textLocation:String
    },
    website: String,
    picture: String,
    yourstory: String, 
    idealcarer:String,
    membership:{
      plan:String,
      lastPaymentOn:Date,
      paymentDue:Date,
      pricing:Number,
      discount:Number
    },
    availaibilty:{
      dayOfWeek:String,
      beforeSchool:Boolean,
      day:Boolean,
      afterSchool:Boolean,
      evening:Boolean
    },
    description:String,
    responsibilities:String,
    idealjob:String,
    tags: String,
    preferences: String,
    experience:String,
    education:String,
    skillsEndorsements:String,
    recommendations:String,
    accomplishments:String,
    credentials: {
      policeCheck:String,
      referenceCheck:String,
      photoVerification:String,
      wwcCheck:String,
      resumeCheck:String,
      educationCheck:String,
      status:{
        policeCheck:Boolean,
        referenceCheck:Boolean,
        photoVerification:Boolean,
        wwcCheck:Boolean,
        resumeCheck:Boolean,
        educationCheck:Boolean
      }
    }
  }
}, { timestamps: true });

/**
 * Password hash middleware.
 */
userSchema.pre('save', function save(next) {
  const user = this;
  if (!user.isModified('password')) { return next(); }
  bcrypt.genSalt(10, (err, salt) => {
    if (err) { return next(err); }
    bcrypt.hash(user.password, salt, null, (err, hash) => {
      if (err) { return next(err); }
      user.password = hash;
      next();
    });
  });
});

/**
 * Helper method for validating user's password.
 */
userSchema.methods.comparePassword = function comparePassword(candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, (err, isMatch) => {
    cb(err, isMatch);
  });
};

/**
 * Helper method for getting user's gravatar.
 */
userSchema.methods.gravatar = function gravatar(size) {
  if (!size) {
    size = 200;
  }
  if (!this.email) {
    return `https://gravatar.com/avatar/?s=${size}&d=retro`;
  }
  const md5 = crypto.createHash('md5').update(this.email).digest('hex');
  return `https://gravatar.com/avatar/${md5}?s=${size}&d=retro`;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
