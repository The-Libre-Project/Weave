//! Type definitions for d3d12.dll.
//!
//! These match the Windows DirectX 12 API types.

use std::ffi::c_void;

/// Windows 128-bit COM/GUID identifier.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

/// Windows UINT (unsigned 32-bit integer).
pub type UINT = u32;

/// COM IUnknown base interface (opaque; only used as a raw pointer).
#[repr(C)]
pub struct IUnknown {
    _private: [u8; 0],
}

/// DirectX 12 feature levels.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureLevel {
    Level11_0 = 0xB000,
    Level11_1 = 0xB100,
    Level12_0 = 0xC000,
    Level12_1 = 0xC100,
    Level12_2 = 0xC200,
}

/// D3D12 device creation flags.
pub type DeviceFlags = u32;

/// D3D12 factory creation flags.
pub type FactoryFlags = u32;

/// Command list types.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandListType {
    Direct = 0,
    Bundle = 1,
    Compute = 2,
    Copy = 3,
    VideoDecode = 4,
    VideoProcess = 5,
    VideoEncode = 6,
}

/// Command queue priorities.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandQueuePriority {
    Normal = 0,
    High = 100,
    GlobalRealtime = 10000,
}

/// Command queue flags.
pub type CommandQueueFlags = u32;

/// Descriptor heap types.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorHeapType {
    CbvSrvUav = 0,
    Sampler = 1,
    Rtv = 2,
    Dsv = 3,
    NumTypes = 4,
}

/// Descriptor heap flags.
pub type DescriptorHeapFlags = u32;

/// Resource states.
pub type ResourceStates = u32;

/// Resource dimensions.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceDimension {
    Unknown = 0,
    Buffer = 1,
    Texture1D = 2,
    Texture2D = 3,
    Texture3D = 4,
}

/// Resource flags.
pub type ResourceFlags = u32;

/// Heap types.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapType {
    Default = 1,
    Upload = 2,
    Readback = 3,
    Custom = 4,
}

/// CPU page properties.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuPageProperty {
    Unknown = 0,
    NotAvailable = 1,
    WriteCombine = 2,
    WriteBack = 3,
}

/// Memory pool.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryPool {
    Unknown = 0,
    L0 = 1,
    L1 = 2,
}

/// Heap flags.
pub type HeapFlags = u32;

/// Root signature flags.
pub type RootSignatureFlags = u32;

/// Pipeline state subobject types.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineStateSubobjectType {
    RootSignature = 0,
    Vs = 1,
    Ps = 2,
    Ds = 3,
    Hs = 4,
    Gs = 5,
    Cs = 6,
    StreamOutput = 7,
    Blend = 8,
    SampleMask = 9,
    Rasterizer = 10,
    DepthStencil = 11,
    InputLayout = 12,
    IbStripCutValue = 13,
    PrimitiveTopology = 14,
    RenderTargets = 15,
    DepthStencilFormat = 16,
    SampleDesc = 17,
    NodeMask = 18,
    CachedPso = 19,
    Flags = 20,
    DepthStencil1 = 21,
    ViewInstancing = 22,
    As = 23,
    Ms = 24,
}

/// Primitive topology types.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimitiveTopologyType {
    Undefined = 0,
    Point = 1,
    Line = 2,
    Triangle = 3,
    Patch = 4,
}

/// Input classification.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputClassification {
    PerVertexData = 0,
    PerInstanceData = 1,
}

/// Fill modes.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillMode {
    Wireframe = 2,
    Solid = 3,
}

/// Cull modes.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CullMode {
    None = 1,
    Front = 2,
    Back = 3,
}

/// Blend operations.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlendOp {
    Add = 1,
    Subtract = 2,
    RevSubtract = 3,
    Min = 4,
    Max = 5,
}

/// Blend factors.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blend {
    Zero = 1,
    One = 2,
    SrcColor = 3,
    InvSrcColor = 4,
    SrcAlpha = 5,
    InvSrcAlpha = 6,
    DestAlpha = 7,
    InvDestAlpha = 8,
    DestColor = 9,
    InvDestColor = 10,
    SrcAlphaSat = 11,
    BlendFactor = 14,
    InvBlendFactor = 15,
    Src1Color = 16,
    InvSrc1Color = 17,
    Src1Alpha = 18,
    InvSrc1Alpha = 19,
}

/// Logic operations.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicOp {
    Clear = 0,
    Set = 1,
    Copy = 2,
    CopyInverted = 3,
    Noop = 4,
    Invert = 5,
    And = 6,
    Nand = 7,
    Or = 8,
    Nor = 9,
    Xor = 10,
    Equiv = 11,
    AndReverse = 12,
    AndInverted = 13,
    OrReverse = 14,
    OrInverted = 15,
}

/// Depth write masks.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepthWriteMask {
    Zero = 0,
    All = 1,
}

/// Comparison functions.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonFunc {
    Never = 1,
    Less = 2,
    Equal = 3,
    LessEqual = 4,
    Greater = 5,
    NotEqual = 6,
    GreaterEqual = 7,
    Always = 8,
}

/// Stencil operations.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StencilOp {
    Keep = 1,
    Zero = 2,
    Replace = 3,
    IncrSat = 4,
    DecrSat = 5,
    Invert = 6,
    Incr = 7,
    Decr = 8,
}

/// Index buffer strip cut values.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexBufferStripCutValue {
    Disabled = 0,
    Value0xFFFF = 1,
    Value0xFFFFFFFF = 2,
}

/// Pipeline state flags.
pub type PipelineStateFlags = u32;

/// Filter types for samplers.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    MinMagMipPoint = 0,
    MinMagPointMipLinear = 1,
    MinPointMagLinearMipPoint = 4,
    MinPointMagMipLinear = 5,
    MinLinearMagMipPoint = 16,
    MinLinearMagPointMipLinear = 17,
    MinMagLinearMipPoint = 20,
    MinMagMipLinear = 21,
    Anisotropic = 85,
    ComparisonMinMagMipPoint = 128,
    ComparisonMinMagPointMipLinear = 129,
    ComparisonMinPointMagLinearMipPoint = 132,
    ComparisonMinPointMagMipLinear = 133,
    ComparisonMinLinearMagMipPoint = 144,
    ComparisonMinLinearMagPointMipLinear = 145,
    ComparisonMinMagLinearMipPoint = 148,
    ComparisonMinMagMipLinear = 149,
    ComparisonAnisotropic = 213,
    MinimumMinMagMipPoint = 256,
    MinimumMinMagPointMipLinear = 257,
    MinimumMinPointMagLinearMipPoint = 260,
    MinimumMinPointMagMipLinear = 261,
    MinimumMinLinearMagMipPoint = 272,
    MinimumMinLinearMagPointMipLinear = 273,
    MinimumMinMagLinearMipPoint = 276,
    MinimumMinMagMipLinear = 277,
    MinimumAnisotropic = 341,
    MaximumMinMagMipPoint = 384,
    MaximumMinMagPointMipLinear = 385,
    MaximumMinPointMagLinearMipPoint = 388,
    MaximumMinPointMagMipLinear = 389,
    MaximumMinLinearMagMipPoint = 400,
    MaximumMinLinearMagPointMipLinear = 401,
    MaximumMinMagLinearMipPoint = 404,
    MaximumMinMagMipLinear = 405,
    MaximumAnisotropic = 469,
}

/// Texture address modes.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextureAddressMode {
    Wrap = 1,
    Mirror = 2,
    Clamp = 3,
    Border = 4,
    MirrorOnce = 5,
}

/// Static border colors.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticBorderColor {
    TransparentBlack = 0,
    OpaqueBlack = 1,
    OpaqueWhite = 2,
}

/// CPU descriptor handles.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CpuDescriptorHandle {
    pub ptr: usize,
}

/// GPU descriptor handles.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GpuDescriptorHandle {
    pub ptr: u64,
}

/// Resource barriers.
#[repr(C)]
pub struct ResourceBarrier {
    pub ty: ResourceBarrierType,
    pub flags: ResourceBarrierFlags,
    pub barrier: ResourceBarrierUnion,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceBarrierType {
    Transition = 0,
    Aliasing = 1,
    Uav = 2,
}

pub type ResourceBarrierFlags = u32;

#[repr(C)]
pub union ResourceBarrierUnion {
    pub transition: std::mem::ManuallyDrop<ResourceTransitionBarrier>,
    pub aliasing: std::mem::ManuallyDrop<ResourceAliasingBarrier>,
    pub uav: std::mem::ManuallyDrop<ResourceUavBarrier>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ResourceTransitionBarrier {
    pub resource: *mut c_void, // ID3D12Resource*
    pub subresource: UINT,
    pub state_before: ResourceStates,
    pub state_after: ResourceStates,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ResourceAliasingBarrier {
    pub resource_before: *mut c_void, // ID3D12Resource*
    pub resource_after: *mut c_void,  // ID3D12Resource*
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ResourceUavBarrier {
    pub resource: *mut c_void, // ID3D12Resource*
}

/// Viewport structure.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Viewport {
    pub top_left_x: f32,
    pub top_left_y: f32,
    pub width: f32,
    pub height: f32,
    pub min_depth: f32,
    pub max_depth: f32,
}

/// Rectangle structure.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

/// Box structure for 3D regions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Box {
    pub left: UINT,
    pub top: UINT,
    pub front: UINT,
    pub right: UINT,
    pub bottom: UINT,
    pub back: UINT,
}

/// Sample description.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SampleDesc {
    pub count: UINT,
    pub quality: UINT,
}

/// Input element descriptions.
#[repr(C)]
#[derive(Debug)]
pub struct InputElementDesc {
    pub semantic_name: *const u8, // PCSTR
    pub semantic_index: UINT,
    pub format: u32, // DXGI_FORMAT
    pub input_slot: UINT,
    pub aligned_byte_offset: UINT,
    pub input_slot_class: InputClassification,
    pub instance_data_step_rate: UINT,
}

/// Render target blend descriptions.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RenderTargetBlendDesc {
    pub blend_enable: u32,
    pub logic_op_enable: u32,
    pub src_blend: Blend,
    pub dest_blend: Blend,
    pub blend_op: BlendOp,
    pub src_blend_alpha: Blend,
    pub dest_blend_alpha: Blend,
    pub blend_op_alpha: BlendOp,
    pub logic_op: LogicOp,
    pub render_target_write_mask: u8,
}

/// Blend descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct BlendDesc {
    pub alpha_to_coverage_enable: u32,
    pub independent_blend_enable: u32,
    pub render_target: [RenderTargetBlendDesc; 8],
}

/// Rasterizer descriptions.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RasterizerDesc {
    pub fill_mode: FillMode,
    pub cull_mode: CullMode,
    pub front_counter_clockwise: u32,
    pub depth_bias: i32,
    pub depth_bias_clamp: f32,
    pub slope_scaled_depth_bias: f32,
    pub depth_clip_enable: u32,
    pub multisample_enable: u32,
    pub antialiased_line_enable: u32,
    pub forced_sample_count: UINT,
    pub conservative_raster: u32,
}

/// Depth stencil operations.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DepthStencilOpDesc {
    pub stencil_fail_op: StencilOp,
    pub stencil_depth_fail_op: StencilOp,
    pub stencil_pass_op: StencilOp,
    pub stencil_func: ComparisonFunc,
}

/// Depth stencil descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DepthStencilDesc {
    pub depth_enable: u32,
    pub depth_write_mask: DepthWriteMask,
    pub depth_func: ComparisonFunc,
    pub stencil_enable: u32,
    pub stencil_read_mask: u8,
    pub stencil_write_mask: u8,
    pub front_face: DepthStencilOpDesc,
    pub back_face: DepthStencilOpDesc,
}

/// Sampler descriptions.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SamplerDesc {
    pub filter: Filter,
    pub address_u: TextureAddressMode,
    pub address_v: TextureAddressMode,
    pub address_w: TextureAddressMode,
    pub mip_lod_bias: f32,
    pub max_anisotropy: UINT,
    pub comparison_func: ComparisonFunc,
    pub border_color: [f32; 4],
    pub min_lod: f32,
    pub max_lod: f32,
}

/// Graphics pipeline state descriptions.
#[repr(C)]
#[derive(Debug)]
pub struct GraphicsPipelineStateDesc {
    pub root_signature: *mut c_void, // ID3D12RootSignature*
    pub vs: ShaderBytecode,
    pub ps: ShaderBytecode,
    pub ds: ShaderBytecode,
    pub hs: ShaderBytecode,
    pub gs: ShaderBytecode,
    pub stream_output: StreamOutputDesc,
    pub blend_state: BlendDesc,
    pub sample_mask: UINT,
    pub rasterizer_state: RasterizerDesc,
    pub depth_stencil_state: DepthStencilDesc,
    pub input_layout: InputLayoutDesc,
    pub ib_strip_cut_value: IndexBufferStripCutValue,
    pub primitive_topology_type: PrimitiveTopologyType,
    pub rtv_formats: [u32; 8], // DXGI_FORMAT
    pub dsv_format: u32, // DXGI_FORMAT
    pub sample_desc: SampleDesc,
    pub node_mask: UINT,
    pub cached_pso: CachedPipelineState,
    pub flags: PipelineStateFlags,
}

/// Shader bytecode.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ShaderBytecode {
    pub bytecode: *const c_void,
    pub bytecode_length: usize,
}

/// Stream output descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct StreamOutputDesc {
    pub so_declaration: *const StreamOutputDeclarationEntry,
    pub num_entries: UINT,
    pub buffer_strides: *const UINT,
    pub num_strides: UINT,
    pub rasterized_stream: UINT,
}

/// Stream output declaration entries.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct StreamOutputDeclarationEntry {
    pub stream: UINT,
    pub semantic_name: *const u8, // PCSTR
    pub semantic_index: UINT,
    pub start_component: u8,
    pub component_count: u8,
    pub output_slot: u8,
}

/// Input layout descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct InputLayoutDesc {
    pub input_element_descs: *const InputElementDesc,
    pub num_elements: UINT,
}

/// Cached pipeline state.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CachedPipelineState {
    pub cached_blob: *const c_void,
    pub cached_blob_size_in_bytes: usize,
}

/// Compute pipeline state descriptions.
#[repr(C)]
#[derive(Debug)]
pub struct ComputePipelineStateDesc {
    pub root_signature: *mut c_void, // ID3D12RootSignature*
    pub cs: ShaderBytecode,
    pub node_mask: UINT,
    pub cached_pso: CachedPipelineState,
    pub flags: PipelineStateFlags,
}

/// Vertex buffer view.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct VertexBufferView {
    pub buffer_location: u64,
    pub size_in_bytes: UINT,
    pub stride_in_bytes: UINT,
}

/// Index buffer view.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct IndexBufferView {
    pub buffer_location: u64,
    pub size_in_bytes: UINT,
    pub format: u32, // DXGI_FORMAT
}

/// Constant buffer view descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ConstantBufferViewDesc {
    pub buffer_location: u64,
    pub size_in_bytes: UINT,
}

/// Shader resource view descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ShaderResourceViewDesc {
    pub format: u32, // DXGI_FORMAT
    pub view_dimension: u32, // D3D12_SRV_DIMENSION
    pub shader_4_component_mapping: UINT,
    pub texture_2d: ShaderResourceViewDescTexture2D,
}

/// SRV texture 2D descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ShaderResourceViewDescTexture2D {
    pub most_detailed_mip: UINT,
    pub mip_levels: UINT,
    pub plane_slice: UINT,
    pub resource_min_lod_clamp: f32,
}

/// Unordered access view descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct UnorderedAccessViewDesc {
    pub format: u32, // DXGI_FORMAT
    pub view_dimension: u32, // D3D12_UAV_DIMENSION
    pub buffer: UnorderedAccessViewDescBuffer,
}

/// UAV buffer descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct UnorderedAccessViewDescBuffer {
    pub first_element: u64,
    pub num_elements: UINT,
    pub structure_byte_stride: UINT,
    pub counter_offset_in_bytes: u64,
    pub flags: UINT,
}

/// Render target view descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RenderTargetViewDesc {
    pub format: u32, // DXGI_FORMAT
    pub view_dimension: u32, // D3D12_RTV_DIMENSION
    pub texture_2d: RenderTargetViewDescTexture2D,
}

/// RTV texture 2D descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RenderTargetViewDescTexture2D {
    pub mip_slice: UINT,
    pub plane_slice: UINT,
}

/// Depth stencil view descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DepthStencilViewDesc {
    pub format: u32, // DXGI_FORMAT
    pub view_dimension: u32, // D3D12_DSV_DIMENSION
    pub flags: u32, // D3D12_DSV_FLAGS
    pub texture_2d: DepthStencilViewDescTexture2D,
}

/// DSV texture 2D descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DepthStencilViewDescTexture2D {
    pub mip_slice: UINT,
}

/// Resource descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ResourceDesc {
    pub dimension: ResourceDimension,
    pub alignment: u64,
    pub width: u64,
    pub height: UINT,
    pub depth_or_array_size: UINT,
    pub mip_levels: UINT,
    pub format: u32, // DXGI_FORMAT
    pub sample_desc: SampleDesc,
    pub layout: u32, // D3D12_TEXTURE_LAYOUT
    pub flags: ResourceFlags,
}

/// Heap properties.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct HeapProperties {
    pub ty: HeapType,
    pub cpu_page_property: CpuPageProperty,
    pub memory_pool_preference: MemoryPool,
    pub creation_node_mask: UINT,
    pub visible_node_mask: UINT,
}

/// Heap descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct HeapDesc {
    pub size_in_bytes: u64,
    pub properties: HeapProperties,
    pub alignment: u64,
    pub flags: HeapFlags,
}

/// Clear value.
#[repr(C)]
pub union ClearValue {
    pub color: [f32; 4],
    pub depth_stencil: std::mem::ManuallyDrop<ClearValueDepthStencil>,
}

/// Clear value for depth/stencil.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ClearValueDepthStencil {
    pub depth: f32,
    pub stencil: u8,
}

/// Root signature descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RootSignatureDesc {
    pub num_parameters: UINT,
    pub parameters: *const RootParameter,
    pub num_static_samplers: UINT,
    pub static_samplers: *const StaticSamplerDesc,
    pub flags: RootSignatureFlags,
}

/// Root parameters.
#[repr(C)]
pub union RootParameter {
    pub descriptor_table: std::mem::ManuallyDrop<RootDescriptorTable>,
    pub constants: std::mem::ManuallyDrop<RootConstants>,
    pub descriptor: std::mem::ManuallyDrop<RootDescriptor>,
}

/// Root descriptor tables.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RootDescriptorTable {
    pub num_descriptor_ranges: UINT,
    pub descriptor_ranges: *const DescriptorRange,
}

/// Root constants.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RootConstants {
    pub shader_register: UINT,
    pub register_space: UINT,
    pub num_32_bit_values: UINT,
}

/// Root descriptors.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RootDescriptor {
    pub shader_register: UINT,
    pub register_space: UINT,
}

/// Descriptor ranges.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DescriptorRange {
    pub range_type: u32, // D3D12_DESCRIPTOR_RANGE_TYPE
    pub num_descriptors: UINT,
    pub base_shader_register: UINT,
    pub register_space: UINT,
    pub offset_in_descriptors_from_table_start: UINT,
}

/// Static sampler descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct StaticSamplerDesc {
    pub filter: Filter,
    pub address_u: TextureAddressMode,
    pub address_v: TextureAddressMode,
    pub address_w: TextureAddressMode,
    pub mip_lod_bias: f32,
    pub max_anisotropy: UINT,
    pub comparison_func: ComparisonFunc,
    pub border_color: StaticBorderColor,
    pub min_lod: f32,
    pub max_lod: f32,
    pub shader_register: UINT,
    pub register_space: UINT,
    pub shader_visibility: u32, // D3D12_SHADER_VISIBILITY
}

/// Descriptor heap descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DescriptorHeapDesc {
    pub ty: DescriptorHeapType,
    pub num_descriptors: UINT,
    pub flags: DescriptorHeapFlags,
    pub node_mask: UINT,
}

/// Command queue descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CommandQueueDesc {
    pub ty: CommandListType,
    pub priority: CommandQueuePriority,
    pub flags: CommandQueueFlags,
    pub node_mask: UINT,
}

/// Command allocator descriptions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CommandAllocatorDesc {
    pub ty: CommandListType,
}