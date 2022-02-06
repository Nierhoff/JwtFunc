using Microsoft.VisualStudio.TestTools.UnitTesting;
using JwtFunc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using System.Security.Cryptography.X509Certificates;
using System.Security.Claims;

namespace JwtFunc.Tests
{
    [TestClass()]
    public class Function1Tests
    {

        static ILoggerFactory loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
        ILogger<Function1> logger = loggerFactory.CreateLogger<Function1>();

        [TestMethod()]
        public void GenereteTest()
        {
            string token = new Function1(loggerFactory).Generete();
            logger.LogInformation(token);
            Assert.IsTrue(token.Contains("."));
            var segments = token.Split(".");
            Assert.AreEqual(3, segments.Length);
            string jose = segments.First();
            string claims = segments[1];
            string signature = segments[2];
        }

        [TestMethod()]
        public void ValidateTest()
        {
            string token = new Function1(loggerFactory).Generete();
            ClaimsPrincipal princ = new Function1(loggerFactory).Validate(token);
            logger.LogInformation(princ.Claims.ToString());
        }

        [TestMethod()]
        public void loadCertTest()
        {
            X509Certificate2 cert = new Function1(loggerFactory).loadCert();
            logger.LogInformation(cert.Issuer);
            Assert.AreEqual("O=Default Company Ltd, L=Default City, C=XX", cert.Issuer);
        }
    }
}