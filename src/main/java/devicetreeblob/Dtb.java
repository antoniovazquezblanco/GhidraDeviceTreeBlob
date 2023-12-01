// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild
package devicetreeblob;

import io.kaitai.struct.ByteBufferKaitaiStream;
import io.kaitai.struct.KaitaiStruct;
import io.kaitai.struct.KaitaiStream;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.Arrays;
import java.util.ArrayList;
import java.nio.charset.Charset;

/**
 * Also referred to as Devicetree Blob (DTB). It is a flat binary encoding
 * of data (primarily devicetree data, although other data is possible as well).
 * The data is internally stored as a tree of named nodes and properties. Nodes
 * contain properties and child nodes, while properties are name-value pairs.
 * 
 * The Devicetree Blobs (`.dtb` files) are compiled from the Devicetree Source
 * files (`.dts`) through the Devicetree compiler (DTC).
 * 
 * On Linux systems that support this, the blobs can be accessed in
 * `/sys/firmware/fdt`:
 * 
 * * <https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-firmware-ofw>
 * 
 * The encoding of strings used in the `strings_block` and `structure_block` is
 * actually a subset of ASCII:
 * 
 * <https://devicetree-specification.readthedocs.io/en/v0.3/devicetree-basics.html#node-names>
 * 
 * Example files:
 * 
 * * <https://github.com/qemu/qemu/tree/master/pc-bios>
 * @see <a href="https://devicetree-specification.readthedocs.io/en/v0.3/flattened-format.html">Source</a>
 * @see <a href="https://elinux.org/images/f/f4/Elc2013_Fernandes.pdf">Source</a>
 */
public class Dtb extends KaitaiStruct {
    public static Dtb fromFile(String fileName) throws IOException {
        return new Dtb(new ByteBufferKaitaiStream(fileName));
    }

    public enum Fdt {
        BEGIN_NODE(1),
        END_NODE(2),
        PROP(3),
        NOP(4),
        END(9);

        private final long id;
        Fdt(long id) { this.id = id; }
        public long id() { return id; }
        private static final Map<Long, Fdt> byId = new HashMap<Long, Fdt>(5);
        static {
            for (Fdt e : Fdt.values())
                byId.put(e.id(), e);
        }
        public static Fdt byId(long id) { return byId.get(id); }
    }

    public Dtb(KaitaiStream _io) {
        this(_io, null, null);
    }

    public Dtb(KaitaiStream _io, KaitaiStruct _parent) {
        this(_io, _parent, null);
    }

    public Dtb(KaitaiStream _io, KaitaiStruct _parent, Dtb _root) {
        super(_io);
        this._parent = _parent;
        this._root = _root == null ? this : _root;
        _read();
    }
    private void _read() {
        this.magic = this._io.readBytes(4);
        if (!(Arrays.equals(magic(), new byte[] { -48, 13, -2, -19 }))) {
            throw new KaitaiStream.ValidationNotEqualError(new byte[] { -48, 13, -2, -19 }, magic(), _io(), "/seq/0");
        }
        this.totalSize = this._io.readU4be();
        this.ofsStructureBlock = this._io.readU4be();
        this.ofsStringsBlock = this._io.readU4be();
        this.ofsMemoryReservationBlock = this._io.readU4be();
        this.version = this._io.readU4be();
        this.minCompatibleVersion = this._io.readU4be();
        if (!(minCompatibleVersion() <= version())) {
            throw new KaitaiStream.ValidationGreaterThanError(version(), minCompatibleVersion(), _io(), "/seq/6");
        }
        this.bootCpuidPhys = this._io.readU4be();
        this.lenStringsBlock = this._io.readU4be();
        this.lenStructureBlock = this._io.readU4be();
    }
    public static class MemoryBlock extends KaitaiStruct {
        public static MemoryBlock fromFile(String fileName) throws IOException {
            return new MemoryBlock(new ByteBufferKaitaiStream(fileName));
        }

        public MemoryBlock(KaitaiStream _io) {
            this(_io, null, null);
        }

        public MemoryBlock(KaitaiStream _io, Dtb _parent) {
            this(_io, _parent, null);
        }

        public MemoryBlock(KaitaiStream _io, Dtb _parent, Dtb _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.entries = new ArrayList<MemoryBlockEntry>();
            {
                int i = 0;
                while (!this._io.isEof()) {
                    this.entries.add(new MemoryBlockEntry(this._io, this, _root));
                    i++;
                }
            }
        }
        private ArrayList<MemoryBlockEntry> entries;
        private Dtb _root;
        private Dtb _parent;
        public ArrayList<MemoryBlockEntry> entries() { return entries; }
        public Dtb _root() { return _root; }
        public Dtb _parent() { return _parent; }
    }
    public static class FdtBlock extends KaitaiStruct {
        public static FdtBlock fromFile(String fileName) throws IOException {
            return new FdtBlock(new ByteBufferKaitaiStream(fileName));
        }

        public FdtBlock(KaitaiStream _io) {
            this(_io, null, null);
        }

        public FdtBlock(KaitaiStream _io, Dtb _parent) {
            this(_io, _parent, null);
        }

        public FdtBlock(KaitaiStream _io, Dtb _parent, Dtb _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.nodes = new ArrayList<FdtNode>();
            {
                FdtNode _it;
                int i = 0;
                do {
                    _it = new FdtNode(this._io, this, _root);
                    this.nodes.add(_it);
                    i++;
                } while (!(_it.type() == Dtb.Fdt.END));
            }
        }
        private ArrayList<FdtNode> nodes;
        private Dtb _root;
        private Dtb _parent;
        public ArrayList<FdtNode> nodes() { return nodes; }
        public Dtb _root() { return _root; }
        public Dtb _parent() { return _parent; }
    }
    public static class MemoryBlockEntry extends KaitaiStruct {
        public static MemoryBlockEntry fromFile(String fileName) throws IOException {
            return new MemoryBlockEntry(new ByteBufferKaitaiStream(fileName));
        }

        public MemoryBlockEntry(KaitaiStream _io) {
            this(_io, null, null);
        }

        public MemoryBlockEntry(KaitaiStream _io, Dtb.MemoryBlock _parent) {
            this(_io, _parent, null);
        }

        public MemoryBlockEntry(KaitaiStream _io, Dtb.MemoryBlock _parent, Dtb _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.address = this._io.readU8be();
            this.size = this._io.readU8be();
        }
        private long address;
        private long size;
        private Dtb _root;
        private Dtb.MemoryBlock _parent;
        /**
         * physical address of a reserved memory region
         */
        public long address() { return address; }

        /**
         * size of a reserved memory region
         */
        public long size() { return size; }
        public Dtb _root() { return _root; }
        public Dtb.MemoryBlock _parent() { return _parent; }
    }
    public static class Strings extends KaitaiStruct {
        public static Strings fromFile(String fileName) throws IOException {
            return new Strings(new ByteBufferKaitaiStream(fileName));
        }

        public Strings(KaitaiStream _io) {
            this(_io, null, null);
        }

        public Strings(KaitaiStream _io, Dtb _parent) {
            this(_io, _parent, null);
        }

        public Strings(KaitaiStream _io, Dtb _parent, Dtb _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.strings = new ArrayList<String>();
            {
                int i = 0;
                while (!this._io.isEof()) {
                    this.strings.add(new String(this._io.readBytesTerm((byte) 0, false, true, true), Charset.forName("ASCII")));
                    i++;
                }
            }
        }
        private ArrayList<String> strings;
        private Dtb _root;
        private Dtb _parent;
        public ArrayList<String> strings() { return strings; }
        public Dtb _root() { return _root; }
        public Dtb _parent() { return _parent; }
    }
    public static class FdtProp extends KaitaiStruct {
        public static FdtProp fromFile(String fileName) throws IOException {
            return new FdtProp(new ByteBufferKaitaiStream(fileName));
        }

        public FdtProp(KaitaiStream _io) {
            this(_io, null, null);
        }

        public FdtProp(KaitaiStream _io, Dtb.FdtNode _parent) {
            this(_io, _parent, null);
        }

        public FdtProp(KaitaiStream _io, Dtb.FdtNode _parent, Dtb _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.lenProperty = this._io.readU4be();
            this.ofsName = this._io.readU4be();
            this.property = this._io.readBytes(lenProperty());
            this.padding = this._io.readBytes(KaitaiStream.mod(-(_io().pos()), 4));
        }
        private String name;
        public String name() {
            if (this.name != null)
                return this.name;
            KaitaiStream io = _root().stringsBlock()._io();
            long _pos = io.pos();
            io.seek(ofsName());
            this.name = new String(io.readBytesTerm((byte) 0, false, true, true), Charset.forName("ASCII"));
            io.seek(_pos);
            return this.name;
        }
        private long lenProperty;
        private long ofsName;
        private byte[] property;
        private byte[] padding;
        private Dtb _root;
        private Dtb.FdtNode _parent;
        public long lenProperty() { return lenProperty; }
        public long ofsName() { return ofsName; }
        public byte[] property() { return property; }
        public byte[] padding() { return padding; }
        public Dtb _root() { return _root; }
        public Dtb.FdtNode _parent() { return _parent; }
    }
    public static class FdtNode extends KaitaiStruct {
        public static FdtNode fromFile(String fileName) throws IOException {
            return new FdtNode(new ByteBufferKaitaiStream(fileName));
        }

        public FdtNode(KaitaiStream _io) {
            this(_io, null, null);
        }

        public FdtNode(KaitaiStream _io, Dtb.FdtBlock _parent) {
            this(_io, _parent, null);
        }

        public FdtNode(KaitaiStream _io, Dtb.FdtBlock _parent, Dtb _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.type = Dtb.Fdt.byId(this._io.readU4be());
            {
                Fdt on = type();
                if (on != null) {
                    switch (type()) {
                    case BEGIN_NODE: {
                        this.body = new FdtBeginNode(this._io, this, _root);
                        break;
                    }
                    case PROP: {
                        this.body = new FdtProp(this._io, this, _root);
                        break;
                    }
                    }
                }
            }
        }
        private Fdt type;
        private KaitaiStruct body;
        private Dtb _root;
        private Dtb.FdtBlock _parent;
        public Fdt type() { return type; }
        public KaitaiStruct body() { return body; }
        public Dtb _root() { return _root; }
        public Dtb.FdtBlock _parent() { return _parent; }
    }
    public static class FdtBeginNode extends KaitaiStruct {
        public static FdtBeginNode fromFile(String fileName) throws IOException {
            return new FdtBeginNode(new ByteBufferKaitaiStream(fileName));
        }

        public FdtBeginNode(KaitaiStream _io) {
            this(_io, null, null);
        }

        public FdtBeginNode(KaitaiStream _io, Dtb.FdtNode _parent) {
            this(_io, _parent, null);
        }

        public FdtBeginNode(KaitaiStream _io, Dtb.FdtNode _parent, Dtb _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.name = new String(this._io.readBytesTerm((byte) 0, false, true, true), Charset.forName("ASCII"));
            this.padding = this._io.readBytes(KaitaiStream.mod(-(_io().pos()), 4));
        }
        private String name;
        private byte[] padding;
        private Dtb _root;
        private Dtb.FdtNode _parent;
        public String name() { return name; }
        public byte[] padding() { return padding; }
        public Dtb _root() { return _root; }
        public Dtb.FdtNode _parent() { return _parent; }
    }
    private MemoryBlock memoryReservationBlock;
    public MemoryBlock memoryReservationBlock() {
        if (this.memoryReservationBlock != null)
            return this.memoryReservationBlock;
        long _pos = this._io.pos();
        this._io.seek(ofsMemoryReservationBlock());
        this._raw_memoryReservationBlock = this._io.readBytes((ofsStructureBlock() - ofsMemoryReservationBlock()));
        KaitaiStream _io__raw_memoryReservationBlock = new ByteBufferKaitaiStream(_raw_memoryReservationBlock);
        this.memoryReservationBlock = new MemoryBlock(_io__raw_memoryReservationBlock, this, _root);
        this._io.seek(_pos);
        return this.memoryReservationBlock;
    }
    private FdtBlock structureBlock;
    public FdtBlock structureBlock() {
        if (this.structureBlock != null)
            return this.structureBlock;
        long _pos = this._io.pos();
        this._io.seek(ofsStructureBlock());
        this._raw_structureBlock = this._io.readBytes(lenStructureBlock());
        KaitaiStream _io__raw_structureBlock = new ByteBufferKaitaiStream(_raw_structureBlock);
        this.structureBlock = new FdtBlock(_io__raw_structureBlock, this, _root);
        this._io.seek(_pos);
        return this.structureBlock;
    }
    private Strings stringsBlock;
    public Strings stringsBlock() {
        if (this.stringsBlock != null)
            return this.stringsBlock;
        long _pos = this._io.pos();
        this._io.seek(ofsStringsBlock());
        this._raw_stringsBlock = this._io.readBytes(lenStringsBlock());
        KaitaiStream _io__raw_stringsBlock = new ByteBufferKaitaiStream(_raw_stringsBlock);
        this.stringsBlock = new Strings(_io__raw_stringsBlock, this, _root);
        this._io.seek(_pos);
        return this.stringsBlock;
    }
    private byte[] magic;
    private long totalSize;
    private long ofsStructureBlock;
    private long ofsStringsBlock;
    private long ofsMemoryReservationBlock;
    private long version;
    private long minCompatibleVersion;
    private long bootCpuidPhys;
    private long lenStringsBlock;
    private long lenStructureBlock;
    private Dtb _root;
    private KaitaiStruct _parent;
    private byte[] _raw_memoryReservationBlock;
    private byte[] _raw_structureBlock;
    private byte[] _raw_stringsBlock;
    public byte[] magic() { return magic; }
    public long totalSize() { return totalSize; }
    public long ofsStructureBlock() { return ofsStructureBlock; }
    public long ofsStringsBlock() { return ofsStringsBlock; }
    public long ofsMemoryReservationBlock() { return ofsMemoryReservationBlock; }
    public long version() { return version; }
    public long minCompatibleVersion() { return minCompatibleVersion; }
    public long bootCpuidPhys() { return bootCpuidPhys; }
    public long lenStringsBlock() { return lenStringsBlock; }
    public long lenStructureBlock() { return lenStructureBlock; }
    public Dtb _root() { return _root; }
    public KaitaiStruct _parent() { return _parent; }
    public byte[] _raw_memoryReservationBlock() { return _raw_memoryReservationBlock; }
    public byte[] _raw_structureBlock() { return _raw_structureBlock; }
    public byte[] _raw_stringsBlock() { return _raw_stringsBlock; }
}
