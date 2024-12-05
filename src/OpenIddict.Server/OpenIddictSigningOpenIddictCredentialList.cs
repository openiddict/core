using System.Collections;
using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server
{
    public class OpenIddictSigningOpenIddictCredentialList: 
        IOpenIddictCredentialList<SigningCredentials>
    {
        private OpenIddictSigningCredentialsComparer comparer;
        private readonly object _setLock = new();
        private IImmutableSet<SigningCredentials> _internalSet;

        public OpenIddictSigningOpenIddictCredentialList(SigningCredentials[] initialValues, OpenIddictSigningCredentialsComparer? inputComp)
        {
            comparer = inputComp ?? OpenIddictSigningCredentialsComparer.DefaultInstance;
            _internalSet = ImmutableSortedSet.Create(comparer, initialValues);
        }
        
        public SigningCredentials this[int index]  
        {
            get
            {
                lock (_setLock)
                {
                    return _internalSet.ToArray()[index];
                }
            }
        }
        
        public bool TrueForAll(Predicate<SigningCredentials> match)
        {
            lock (_setLock)
            {
                return _internalSet.All(x => match(x));
            }
        }

        public bool Exists(Predicate<SigningCredentials> match)
        {
            lock (_setLock)
            {
                return _internalSet.Any(x => match(x));
            }
        }

        public SigningCredentials? Find(Predicate<SigningCredentials> match)
        {
            lock (_setLock)
            {
                return _internalSet.FirstOrDefault(x => match(x));
            }
        }

        public void Add(SigningCredentials item)
        {
            lock (_setLock)
            {
                if (string.IsNullOrEmpty(item.Key.KeyId))
                {
                    item.Key.KeyId = OpenIddictSecurityKeyExtensions.GetKeyIdentifier(item.Key);
                }
            
                _internalSet = _internalSet.Add(item);
            }
        }

        public void AddRange(IEnumerable<SigningCredentials> items)
        {
            lock (_setLock)
            {
                List<SigningCredentials>? itemsList = items.ToList();
                foreach (SigningCredentials? item in itemsList.Where(item => string.IsNullOrEmpty(item.Key.KeyId)))
                {
                    item.Key.KeyId = OpenIddictSecurityKeyExtensions.GetKeyIdentifier(item.Key);
                }

                _internalSet = _internalSet.Union(itemsList);
            }
        }

        public void Remove(string keyId)
        {
            lock (_setLock)
            {
                SigningCredentials? itemToRemove = _internalSet.FirstOrDefault(x => x.Key.KeyId == keyId);

                if (itemToRemove == null) throw new Exception("NotFound");
            
                _internalSet = _internalSet.Remove(itemToRemove);
            }
        }

        public IEnumerator<SigningCredentials> GetEnumerator()
        {
            lock (_setLock)
            {
                return _internalSet.GetEnumerator();
            }
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            lock (_setLock)
            {
                return _internalSet.GetEnumerator();
            }
        }

        public void Clear()
        {
            lock (_setLock)
            {
                _internalSet = _internalSet.Clear();
            }
        }
    }
}