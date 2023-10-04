namespace OpenIdDictMvcLib.Dto
{
    public class PageDto
    {
        public int CurrentPage { get; set; } = 0;
        public int PageSize { get; set; } = 0;
        public int PageCount { get; set; } = 0;
        public int PrintFrom { get; set; } = 0;
        public int PrintTo { get; set; } = 0;
    }
}
