// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: AbilityMetaModifierDurabilityChange.proto

package emu.grasscutter.net.proto;

public final class AbilityMetaModifierDurabilityChangeOuterClass {
  private AbilityMetaModifierDurabilityChangeOuterClass() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  public interface AbilityMetaModifierDurabilityChangeOrBuilder extends
      // @@protoc_insertion_point(interface_extends:AbilityMetaModifierDurabilityChange)
      com.google.protobuf.MessageOrBuilder {

    /**
     * <code>float remain_durability = 13;</code>
     * @return The remainDurability.
     */
    float getRemainDurability();

    /**
     * <code>float Unk3300_IFHFHEHDOIO = 1;</code>
     * @return The unk3300IFHFHEHDOIO.
     */
    float getUnk3300IFHFHEHDOIO();
  }
  /**
   * Protobuf type {@code AbilityMetaModifierDurabilityChange}
   */
  public static final class AbilityMetaModifierDurabilityChange extends
      com.google.protobuf.GeneratedMessageV3 implements
      // @@protoc_insertion_point(message_implements:AbilityMetaModifierDurabilityChange)
      AbilityMetaModifierDurabilityChangeOrBuilder {
  private static final long serialVersionUID = 0L;
    // Use AbilityMetaModifierDurabilityChange.newBuilder() to construct.
    private AbilityMetaModifierDurabilityChange(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
      super(builder);
    }
    private AbilityMetaModifierDurabilityChange() {
    }

    @java.lang.Override
    @SuppressWarnings({"unused"})
    protected java.lang.Object newInstance(
        UnusedPrivateParameter unused) {
      return new AbilityMetaModifierDurabilityChange();
    }

    @java.lang.Override
    public final com.google.protobuf.UnknownFieldSet
    getUnknownFields() {
      return this.unknownFields;
    }
    private AbilityMetaModifierDurabilityChange(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      this();
      if (extensionRegistry == null) {
        throw new java.lang.NullPointerException();
      }
      com.google.protobuf.UnknownFieldSet.Builder unknownFields =
          com.google.protobuf.UnknownFieldSet.newBuilder();
      try {
        boolean done = false;
        while (!done) {
          int tag = input.readTag();
          switch (tag) {
            case 0:
              done = true;
              break;
            case 13: {

              unk3300IFHFHEHDOIO_ = input.readFloat();
              break;
            }
            case 109: {

              remainDurability_ = input.readFloat();
              break;
            }
            default: {
              if (!parseUnknownField(
                  input, unknownFields, extensionRegistry, tag)) {
                done = true;
              }
              break;
            }
          }
        }
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        throw e.setUnfinishedMessage(this);
      } catch (java.io.IOException e) {
        throw new com.google.protobuf.InvalidProtocolBufferException(
            e).setUnfinishedMessage(this);
      } finally {
        this.unknownFields = unknownFields.build();
        makeExtensionsImmutable();
      }
    }
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.internal_static_AbilityMetaModifierDurabilityChange_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.internal_static_AbilityMetaModifierDurabilityChange_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange.class, emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange.Builder.class);
    }

    public static final int REMAIN_DURABILITY_FIELD_NUMBER = 13;
    private float remainDurability_;
    /**
     * <code>float remain_durability = 13;</code>
     * @return The remainDurability.
     */
    @java.lang.Override
    public float getRemainDurability() {
      return remainDurability_;
    }

    public static final int UNK3300_IFHFHEHDOIO_FIELD_NUMBER = 1;
    private float unk3300IFHFHEHDOIO_;
    /**
     * <code>float Unk3300_IFHFHEHDOIO = 1;</code>
     * @return The unk3300IFHFHEHDOIO.
     */
    @java.lang.Override
    public float getUnk3300IFHFHEHDOIO() {
      return unk3300IFHFHEHDOIO_;
    }

    private byte memoizedIsInitialized = -1;
    @java.lang.Override
    public final boolean isInitialized() {
      byte isInitialized = memoizedIsInitialized;
      if (isInitialized == 1) return true;
      if (isInitialized == 0) return false;

      memoizedIsInitialized = 1;
      return true;
    }

    @java.lang.Override
    public void writeTo(com.google.protobuf.CodedOutputStream output)
                        throws java.io.IOException {
      if (unk3300IFHFHEHDOIO_ != 0F) {
        output.writeFloat(1, unk3300IFHFHEHDOIO_);
      }
      if (remainDurability_ != 0F) {
        output.writeFloat(13, remainDurability_);
      }
      unknownFields.writeTo(output);
    }

    @java.lang.Override
    public int getSerializedSize() {
      int size = memoizedSize;
      if (size != -1) return size;

      size = 0;
      if (unk3300IFHFHEHDOIO_ != 0F) {
        size += com.google.protobuf.CodedOutputStream
          .computeFloatSize(1, unk3300IFHFHEHDOIO_);
      }
      if (remainDurability_ != 0F) {
        size += com.google.protobuf.CodedOutputStream
          .computeFloatSize(13, remainDurability_);
      }
      size += unknownFields.getSerializedSize();
      memoizedSize = size;
      return size;
    }

    @java.lang.Override
    public boolean equals(final java.lang.Object obj) {
      if (obj == this) {
       return true;
      }
      if (!(obj instanceof emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange)) {
        return super.equals(obj);
      }
      emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange other = (emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange) obj;

      if (java.lang.Float.floatToIntBits(getRemainDurability())
          != java.lang.Float.floatToIntBits(
              other.getRemainDurability())) return false;
      if (java.lang.Float.floatToIntBits(getUnk3300IFHFHEHDOIO())
          != java.lang.Float.floatToIntBits(
              other.getUnk3300IFHFHEHDOIO())) return false;
      if (!unknownFields.equals(other.unknownFields)) return false;
      return true;
    }

    @java.lang.Override
    public int hashCode() {
      if (memoizedHashCode != 0) {
        return memoizedHashCode;
      }
      int hash = 41;
      hash = (19 * hash) + getDescriptor().hashCode();
      hash = (37 * hash) + REMAIN_DURABILITY_FIELD_NUMBER;
      hash = (53 * hash) + java.lang.Float.floatToIntBits(
          getRemainDurability());
      hash = (37 * hash) + UNK3300_IFHFHEHDOIO_FIELD_NUMBER;
      hash = (53 * hash) + java.lang.Float.floatToIntBits(
          getUnk3300IFHFHEHDOIO());
      hash = (29 * hash) + unknownFields.hashCode();
      memoizedHashCode = hash;
      return hash;
    }

    public static emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange parseFrom(
        java.nio.ByteBuffer data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange parseFrom(
        java.nio.ByteBuffer data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange parseFrom(
        com.google.protobuf.ByteString data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange parseFrom(
        com.google.protobuf.ByteString data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange parseFrom(byte[] data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange parseFrom(
        byte[] data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange parseFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange parseFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange parseDelimitedFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange parseDelimitedFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
    }
    public static emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange parseFrom(
        com.google.protobuf.CodedInputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange parseFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }

    @java.lang.Override
    public Builder newBuilderForType() { return newBuilder(); }
    public static Builder newBuilder() {
      return DEFAULT_INSTANCE.toBuilder();
    }
    public static Builder newBuilder(emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange prototype) {
      return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
    }
    @java.lang.Override
    public Builder toBuilder() {
      return this == DEFAULT_INSTANCE
          ? new Builder() : new Builder().mergeFrom(this);
    }

    @java.lang.Override
    protected Builder newBuilderForType(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      Builder builder = new Builder(parent);
      return builder;
    }
    /**
     * Protobuf type {@code AbilityMetaModifierDurabilityChange}
     */
    public static final class Builder extends
        com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
        // @@protoc_insertion_point(builder_implements:AbilityMetaModifierDurabilityChange)
        emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChangeOrBuilder {
      public static final com.google.protobuf.Descriptors.Descriptor
          getDescriptor() {
        return emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.internal_static_AbilityMetaModifierDurabilityChange_descriptor;
      }

      @java.lang.Override
      protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
          internalGetFieldAccessorTable() {
        return emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.internal_static_AbilityMetaModifierDurabilityChange_fieldAccessorTable
            .ensureFieldAccessorsInitialized(
                emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange.class, emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange.Builder.class);
      }

      // Construct using emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange.newBuilder()
      private Builder() {
        maybeForceBuilderInitialization();
      }

      private Builder(
          com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
        super(parent);
        maybeForceBuilderInitialization();
      }
      private void maybeForceBuilderInitialization() {
        if (com.google.protobuf.GeneratedMessageV3
                .alwaysUseFieldBuilders) {
        }
      }
      @java.lang.Override
      public Builder clear() {
        super.clear();
        remainDurability_ = 0F;

        unk3300IFHFHEHDOIO_ = 0F;

        return this;
      }

      @java.lang.Override
      public com.google.protobuf.Descriptors.Descriptor
          getDescriptorForType() {
        return emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.internal_static_AbilityMetaModifierDurabilityChange_descriptor;
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange getDefaultInstanceForType() {
        return emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange.getDefaultInstance();
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange build() {
        emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange result = buildPartial();
        if (!result.isInitialized()) {
          throw newUninitializedMessageException(result);
        }
        return result;
      }

      @java.lang.Override
      public emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange buildPartial() {
        emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange result = new emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange(this);
        result.remainDurability_ = remainDurability_;
        result.unk3300IFHFHEHDOIO_ = unk3300IFHFHEHDOIO_;
        onBuilt();
        return result;
      }

      @java.lang.Override
      public Builder clone() {
        return super.clone();
      }
      @java.lang.Override
      public Builder setField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          java.lang.Object value) {
        return super.setField(field, value);
      }
      @java.lang.Override
      public Builder clearField(
          com.google.protobuf.Descriptors.FieldDescriptor field) {
        return super.clearField(field);
      }
      @java.lang.Override
      public Builder clearOneof(
          com.google.protobuf.Descriptors.OneofDescriptor oneof) {
        return super.clearOneof(oneof);
      }
      @java.lang.Override
      public Builder setRepeatedField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          int index, java.lang.Object value) {
        return super.setRepeatedField(field, index, value);
      }
      @java.lang.Override
      public Builder addRepeatedField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          java.lang.Object value) {
        return super.addRepeatedField(field, value);
      }
      @java.lang.Override
      public Builder mergeFrom(com.google.protobuf.Message other) {
        if (other instanceof emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange) {
          return mergeFrom((emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange)other);
        } else {
          super.mergeFrom(other);
          return this;
        }
      }

      public Builder mergeFrom(emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange other) {
        if (other == emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange.getDefaultInstance()) return this;
        if (other.getRemainDurability() != 0F) {
          setRemainDurability(other.getRemainDurability());
        }
        if (other.getUnk3300IFHFHEHDOIO() != 0F) {
          setUnk3300IFHFHEHDOIO(other.getUnk3300IFHFHEHDOIO());
        }
        this.mergeUnknownFields(other.unknownFields);
        onChanged();
        return this;
      }

      @java.lang.Override
      public final boolean isInitialized() {
        return true;
      }

      @java.lang.Override
      public Builder mergeFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws java.io.IOException {
        emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange parsedMessage = null;
        try {
          parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
        } catch (com.google.protobuf.InvalidProtocolBufferException e) {
          parsedMessage = (emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange) e.getUnfinishedMessage();
          throw e.unwrapIOException();
        } finally {
          if (parsedMessage != null) {
            mergeFrom(parsedMessage);
          }
        }
        return this;
      }

      private float remainDurability_ ;
      /**
       * <code>float remain_durability = 13;</code>
       * @return The remainDurability.
       */
      @java.lang.Override
      public float getRemainDurability() {
        return remainDurability_;
      }
      /**
       * <code>float remain_durability = 13;</code>
       * @param value The remainDurability to set.
       * @return This builder for chaining.
       */
      public Builder setRemainDurability(float value) {
        
        remainDurability_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>float remain_durability = 13;</code>
       * @return This builder for chaining.
       */
      public Builder clearRemainDurability() {
        
        remainDurability_ = 0F;
        onChanged();
        return this;
      }

      private float unk3300IFHFHEHDOIO_ ;
      /**
       * <code>float Unk3300_IFHFHEHDOIO = 1;</code>
       * @return The unk3300IFHFHEHDOIO.
       */
      @java.lang.Override
      public float getUnk3300IFHFHEHDOIO() {
        return unk3300IFHFHEHDOIO_;
      }
      /**
       * <code>float Unk3300_IFHFHEHDOIO = 1;</code>
       * @param value The unk3300IFHFHEHDOIO to set.
       * @return This builder for chaining.
       */
      public Builder setUnk3300IFHFHEHDOIO(float value) {
        
        unk3300IFHFHEHDOIO_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>float Unk3300_IFHFHEHDOIO = 1;</code>
       * @return This builder for chaining.
       */
      public Builder clearUnk3300IFHFHEHDOIO() {
        
        unk3300IFHFHEHDOIO_ = 0F;
        onChanged();
        return this;
      }
      @java.lang.Override
      public final Builder setUnknownFields(
          final com.google.protobuf.UnknownFieldSet unknownFields) {
        return super.setUnknownFields(unknownFields);
      }

      @java.lang.Override
      public final Builder mergeUnknownFields(
          final com.google.protobuf.UnknownFieldSet unknownFields) {
        return super.mergeUnknownFields(unknownFields);
      }


      // @@protoc_insertion_point(builder_scope:AbilityMetaModifierDurabilityChange)
    }

    // @@protoc_insertion_point(class_scope:AbilityMetaModifierDurabilityChange)
    private static final emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange DEFAULT_INSTANCE;
    static {
      DEFAULT_INSTANCE = new emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange();
    }

    public static emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange getDefaultInstance() {
      return DEFAULT_INSTANCE;
    }

    private static final com.google.protobuf.Parser<AbilityMetaModifierDurabilityChange>
        PARSER = new com.google.protobuf.AbstractParser<AbilityMetaModifierDurabilityChange>() {
      @java.lang.Override
      public AbilityMetaModifierDurabilityChange parsePartialFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws com.google.protobuf.InvalidProtocolBufferException {
        return new AbilityMetaModifierDurabilityChange(input, extensionRegistry);
      }
    };

    public static com.google.protobuf.Parser<AbilityMetaModifierDurabilityChange> parser() {
      return PARSER;
    }

    @java.lang.Override
    public com.google.protobuf.Parser<AbilityMetaModifierDurabilityChange> getParserForType() {
      return PARSER;
    }

    @java.lang.Override
    public emu.grasscutter.net.proto.AbilityMetaModifierDurabilityChangeOuterClass.AbilityMetaModifierDurabilityChange getDefaultInstanceForType() {
      return DEFAULT_INSTANCE;
    }

  }

  private static final com.google.protobuf.Descriptors.Descriptor
    internal_static_AbilityMetaModifierDurabilityChange_descriptor;
  private static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_AbilityMetaModifierDurabilityChange_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n)AbilityMetaModifierDurabilityChange.pr" +
      "oto\"]\n#AbilityMetaModifierDurabilityChan" +
      "ge\022\031\n\021remain_durability\030\r \001(\002\022\033\n\023Unk3300" +
      "_IFHFHEHDOIO\030\001 \001(\002B\033\n\031emu.grasscutter.ne" +
      "t.protob\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
        });
    internal_static_AbilityMetaModifierDurabilityChange_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_AbilityMetaModifierDurabilityChange_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_AbilityMetaModifierDurabilityChange_descriptor,
        new java.lang.String[] { "RemainDurability", "Unk3300IFHFHEHDOIO", });
  }

  // @@protoc_insertion_point(outer_class_scope)
}
