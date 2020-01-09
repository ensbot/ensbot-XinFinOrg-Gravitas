'use strict';
module.exports = (sequelize, DataTypes) => {
  const referralLogs = sequelize.define('referralLogs', {
    uniqueId:{
      allowNull:false,
      primaryKey: true,
      type:DataTypes.UUID,
      defaultValue: DataTypes.UUIDV1,
    },
    tokenName:{
        type:DataTypes.STRING,
        allowNull:false
    },
    referralEmail: {
      type: DataTypes.STRING,
      validate:
      {
        isEmail: true,    // checks for email format (foo@bar.com)
      },
      allowNull: false,
    },
    referredEmail:
    {
      type:DataTypes.STRING,
      validate:
      {
        isEmail: true,    // checks for email format (foo@bar.com)
      },
      allowNull:false,
    },
    referralAmount:
    {
      type:DataTypes.FLOAT,
      allowNull:true,
    },
    referredAmount:
    {
      type:DataTypes.FLOAT,
      allowNull:true,
    },
    status:
    {
      type:DataTypes.BOOLEAN,
      defaultValue:false,
    },
    createdAt: {
      allowNull: false,
      type: DataTypes.DATE,
      defaultValue:DataTypes.NOW
    },
    updatedAt: {
      allowNull: false,
      type: DataTypes.DATE,
      defaultValue:DataTypes.NOW
    },
}, {});
  referralLogs.associate = function (models) {
    
  };
  return referralLogs;
};
