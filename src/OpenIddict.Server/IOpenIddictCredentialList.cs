using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server
{
    public interface IOpenIddictCredentialList<T> : IEnumerable<T>
    {
        public abstract SigningCredentials this[int index] { get; }
        public abstract bool TrueForAll(Predicate<T> match);
        public abstract bool Exists(Predicate<T> match);
        public abstract T? Find(Predicate<T> match);
        public abstract void Add(T item);
        public abstract void AddRange(IEnumerable<T> items);
        public abstract void Remove(string keyId);
        public abstract void Clear();
    }
}